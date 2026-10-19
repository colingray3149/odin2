//! Kernel-issued seat identity tokens.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::Sha256;

use crate::error::DomainError;
use crate::ids::{Digest, LaneId, SeatId, SeatTokenId, SessionId, SliceId};

pub const SEAT_TOKEN_SCHEMA_VERSION: u16 = 2;

const SIGNING_DOMAIN: &[u8] = b"odin.seat-token.v2";
const SHA256_LEN: usize = 32;
const SHA256_BASE64URL_LEN: usize = 43;
type HmacSha256 = Hmac<Sha256>;

/// A kernel-issued signed identity primitive bound to one seat, slice, lane, and session.
///
/// Successful verification establishes token integrity, not authorization. All policy and
/// registry revisions are signed so a verifier can reject stale authority without trusting
/// unsigned context.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SeatToken {
    pub schema_version: u16,
    pub seat: SeatId,
    pub slice: SliceId,
    pub lane: LaneId,
    pub session: SessionId,
    pub token_id: SeatTokenId,
    pub seat_revision: Digest,
    pub slice_revision: Digest,
    pub capability_policy_digest: Digest,
    pub context_policy_digest: Digest,
    /// Published snapshot revision used to compose policy digests; absent revisions
    /// require a unique material match among retained publications.
    #[serde(default)]
    pub served_revision: Option<u64>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: String,
}
impl fmt::Debug for SeatToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SeatToken")
            .field("schema_version", &self.schema_version)
            .field("seat", &self.seat)
            .field("slice", &self.slice)
            .field("lane", &self.lane)
            .field("session", &self.session)
            .field("token_id", &self.token_id)
            .field("seat_revision", &self.seat_revision)
            .field("slice_revision", &self.slice_revision)
            .field("capability_policy_digest", &self.capability_policy_digest)
            .field("context_policy_digest", &self.context_policy_digest)
            .field("served_revision", &self.served_revision)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeatTokenWire {
    schema_version: u16,
    seat: SeatId,
    slice: SliceId,
    lane: LaneId,
    session: SessionId,
    token_id: SeatTokenId,
    seat_revision: Digest,
    slice_revision: Digest,
    capability_policy_digest: Digest,
    context_policy_digest: Digest,
    #[serde(default)]
    served_revision: Option<u64>,
    issued_at_ms: u64,
    expires_at_ms: u64,
    signature: String,
}

impl<'de> Deserialize<'de> for SeatToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SeatTokenWire::deserialize(deserializer)?;
        let token = Self {
            schema_version: wire.schema_version,
            seat: wire.seat,
            slice: wire.slice,
            lane: wire.lane,
            session: wire.session,
            token_id: wire.token_id,
            seat_revision: wire.seat_revision,
            slice_revision: wire.slice_revision,
            capability_policy_digest: wire.capability_policy_digest,
            context_policy_digest: wire.context_policy_digest,
            served_revision: wire.served_revision,
            issued_at_ms: wire.issued_at_ms,
            expires_at_ms: wire.expires_at_ms,
            signature: wire.signature,
        };
        token
            .validate_claims()
            .and_then(|()| token.decode_signature().map(|_| ()))
            .map_err(serde::de::Error::custom)?;
        Ok(token)
    }
}
/// Unsigned claims for a version-2 seat token, consumed by [`SeatToken::sign`].
pub struct SeatTokenClaims {
    pub seat: SeatId,
    pub slice: SliceId,
    pub lane: LaneId,
    pub session: SessionId,
    pub token_id: SeatTokenId,
    pub seat_revision: Digest,
    pub slice_revision: Digest,
    pub capability_policy_digest: Digest,
    pub context_policy_digest: Digest,
    /// Optional published snapshot revision; None leaves resolution to retained publications.
    pub served_revision: Option<u64>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl SeatToken {
    /// Signs a complete version-2 token without reading a clock or random source.
    pub fn sign(claims: SeatTokenClaims, key: &[u8]) -> Result<Self, DomainError> {
        let mut token = Self {
            schema_version: SEAT_TOKEN_SCHEMA_VERSION,
            seat: claims.seat,
            slice: claims.slice,
            lane: claims.lane,
            session: claims.session,
            token_id: claims.token_id,
            seat_revision: claims.seat_revision,
            slice_revision: claims.slice_revision,
            capability_policy_digest: claims.capability_policy_digest,
            context_policy_digest: claims.context_policy_digest,
            served_revision: claims.served_revision,
            issued_at_ms: claims.issued_at_ms,
            expires_at_ms: claims.expires_at_ms,
            signature: String::new(),
        };
        token.validate_claims()?;

        let mut mac = new_mac(key);
        token.update_mac(&mut mac);
        token.signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        Ok(token)
    }

    /// Verifies authenticity using constant-time HMAC comparison.
    pub fn verify_signature(&self, key: &[u8]) -> Result<(), DomainError> {
        let signature = self.decode_signature()?;
        let mut mac = new_mac(key);
        self.update_mac(&mut mac);
        mac.verify_slice(&signature)
            .map_err(|_| invalid_token("seat token signature is invalid"))
    }

    /// Verifies authenticity, structural claims, and lifetime at a caller-supplied time.
    pub fn verify_at(&self, key: &[u8], now_ms: u64) -> Result<(), DomainError> {
        self.verify_signature(key)?;
        self.validate_claims()?;
        if now_ms < self.issued_at_ms {
            return Err(invalid_token("seat token is not yet valid"));
        }
        if now_ms >= self.expires_at_ms {
            return Err(DomainError::TokenExpired {
                expires_at_ms: self.expires_at_ms,
                now_ms,
            });
        }
        Ok(())
    }

    fn validate_claims(&self) -> Result<(), DomainError> {
        if self.schema_version != SEAT_TOKEN_SCHEMA_VERSION {
            return Err(invalid_token("seat token schema version is unsupported"));
        }
        if self.issued_at_ms >= self.expires_at_ms {
            return Err(invalid_token("seat token lifetime is invalid"));
        }
        Ok(())
    }

    fn decode_signature(&self) -> Result<[u8; SHA256_LEN], DomainError> {
        if self.signature.len() != SHA256_BASE64URL_LEN {
            return Err(invalid_token("seat token signature is invalid"));
        }

        let mut buffer = [0_u8; SHA256_LEN + 1];
        let decoded_len = URL_SAFE_NO_PAD
            .decode_slice(&self.signature, &mut buffer)
            .map_err(|_| invalid_token("seat token signature is invalid"))?;
        if decoded_len != SHA256_LEN {
            return Err(invalid_token("seat token signature is invalid"));
        }
        let mut decoded = [0_u8; SHA256_LEN];
        decoded.copy_from_slice(&buffer[..SHA256_LEN]);
        Ok(decoded)
    }

    fn update_mac(&self, mac: &mut HmacSha256) {
        self.for_each_signing_chunk(|chunk| mac.update(chunk));
    }

    fn for_each_signing_chunk(&self, mut emit: impl FnMut(&[u8])) {
        emit(SIGNING_DOMAIN);
        emit(&self.schema_version.to_be_bytes());
        emit_string(self.seat.as_str(), &mut emit);
        emit_string(self.slice.as_str(), &mut emit);
        emit_string(self.lane.as_str(), &mut emit);
        emit_string(self.session.as_str(), &mut emit);
        emit_string(self.token_id.as_str(), &mut emit);
        emit(self.seat_revision.as_bytes());
        emit(self.slice_revision.as_bytes());
        emit(self.capability_policy_digest.as_bytes());
        emit(self.context_policy_digest.as_bytes());
        // Append the tagged revision only when present to preserve signatures of tokens without it.
        if let Some(served_revision) = self.served_revision {
            emit(&[1_u8]);
            emit(&served_revision.to_be_bytes());
        }
        emit(&self.issued_at_ms.to_be_bytes());
        emit(&self.expires_at_ms.to_be_bytes());
    }
}

fn emit_string(value: &str, emit: &mut impl FnMut(&[u8])) {
    let len = u32::try_from(value.len()).expect("domain identifiers are bounded below u32::MAX");
    emit(&len.to_be_bytes());
    emit(value.as_bytes());
}

fn new_mac(key: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any size")
}

fn invalid_token(reason: &'static str) -> DomainError {
    DomainError::InvalidToken(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"correct horse battery staple";
    const OTHER_KEY: &[u8] = b"wrong key";

    fn id<T>(parse: impl FnOnce(&str) -> Result<T, DomainError>, value: &str) -> T {
        parse(value).expect("valid id")
    }

    fn token() -> SeatToken {
        signed(Some(7))
    }

    fn signed(served_revision: Option<u64>) -> SeatToken {
        SeatToken::sign(
            SeatTokenClaims {
                seat: id(SeatId::parse, "seat.gungnir"),
                slice: id(SliceId::parse, "slice.build"),
                lane: id(LaneId::parse, "lane.primary"),
                session: id(SessionId::parse, "session-42"),
                token_id: id(SeatTokenId::parse, "seat-token:100:entropy"),
                seat_revision: Digest::hash(b"seat revision"),
                slice_revision: Digest::hash(b"slice revision"),
                capability_policy_digest: Digest::hash(b"capability policy"),
                context_policy_digest: Digest::hash(b"context policy"),
                served_revision,
                issued_at_ms: 100,
                expires_at_ms: 200,
            },
            KEY,
        )
        .expect("valid token")
    }

    #[test]
    fn complete_v2_roundtrip_verifies() {
        let token = token();
        token.verify_signature(KEY).expect("signature verifies");
        token.verify_at(KEY, 150).expect("token is current");

        let encoded = serde_json::to_string(&token).expect("token serializes");
        let decoded: SeatToken = serde_json::from_str(&encoded).expect("token deserializes");
        assert_eq!(decoded, token);
        decoded.verify_at(KEY, 150).expect("roundtrip verifies");
        assert!(!decoded.signature.contains('='));
        assert!(!format!("{decoded:?}").contains(&decoded.signature));
    }

    #[test]
    fn signing_is_deterministic_and_covers_every_claim() {
        let first = token();
        let second = token();
        assert_eq!(first.signature, second.signature);

        let mut variants = Vec::new();
        let mut changed = first.clone();
        changed.schema_version += 1;
        variants.push(changed);
        let mut changed = first.clone();
        changed.seat = id(SeatId::parse, "seat.other");
        variants.push(changed);
        let mut changed = first.clone();
        changed.slice = id(SliceId::parse, "slice.other");
        variants.push(changed);
        let mut changed = first.clone();
        changed.lane = id(LaneId::parse, "lane.other");
        variants.push(changed);
        let mut changed = first.clone();
        changed.session = id(SessionId::parse, "session-other");
        variants.push(changed);
        let mut changed = first.clone();
        changed.token_id = id(SeatTokenId::parse, "seat-token:100:other");
        variants.push(changed);
        let mut changed = first.clone();
        changed.seat_revision = Digest::hash(b"other seat revision");
        variants.push(changed);
        let mut changed = first.clone();
        changed.slice_revision = Digest::hash(b"other slice revision");
        variants.push(changed);
        let mut changed = first.clone();
        changed.capability_policy_digest = Digest::hash(b"other capability policy");
        variants.push(changed);
        let mut changed = first.clone();
        changed.context_policy_digest = Digest::hash(b"other context policy");
        variants.push(changed);
        let mut changed = first.clone();
        changed.served_revision = None;
        variants.push(changed);
        let mut changed = first.clone();
        changed.served_revision = Some(8);
        variants.push(changed);
        let mut changed = first.clone();
        changed.issued_at_ms += 1;
        variants.push(changed);
        let mut changed = first;
        changed.expires_at_ms += 1;
        variants.push(changed);

        for changed in variants {
            assert!(matches!(
                changed.verify_signature(KEY),
                Err(DomainError::InvalidToken(_))
            ));
        }
    }

    #[test]
    fn abbreviated_v1_json_is_rejected() {
        let abbreviated = serde_json::json!({
            "seat": "seat.gungnir",
            "lane": "lane.primary",
            "session": "session-42",
            "issued_at_ms": 100,
            "expires_at_ms": 200,
            "signature": token().signature,
        });
        assert!(serde_json::from_value::<SeatToken>(abbreviated).is_err());
    }

    #[test]
    fn legacy_tokens_stay_signed_law_and_roundtrip_unbound() {
        let legacy = signed(None);
        legacy.verify_signature(KEY).expect("legacy token verifies");
        let encoded = serde_json::to_string(&legacy).expect("legacy token serializes");
        let decoded: SeatToken = serde_json::from_str(&encoded).expect("legacy token parses");
        assert_eq!(decoded, legacy);
        assert_eq!(decoded.served_revision, None);
        let mut promoted = decoded;
        promoted.served_revision = Some(7);
        assert!(
            matches!(
                promoted.verify_signature(KEY),
                Err(DomainError::InvalidToken(_))
            ),
            "a legacy signature must not verify as revision-bound authority"
        );
    }

    #[test]
    fn unknown_claim_is_rejected() {
        let mut encoded = serde_json::to_value(token()).expect("token serializes");
        encoded
            .as_object_mut()
            .expect("token is an object")
            .insert("authority".into(), serde_json::json!("forged"));
        assert!(serde_json::from_value::<SeatToken>(encoded).is_err());
    }

    #[test]
    fn tampered_claim_fails_signature_verification() {
        let mut token = token();
        token.capability_policy_digest = Digest::hash(b"tampered policy");
        assert!(matches!(
            token.verify_signature(KEY),
            Err(DomainError::InvalidToken(_))
        ));
    }

    #[test]
    fn wrong_key_fails_signature_verification() {
        assert!(matches!(
            token().verify_signature(OTHER_KEY),
            Err(DomainError::InvalidToken(_))
        ));
    }

    #[test]
    fn expired_token_is_distinct_from_invalid_signature() {
        assert!(matches!(
            token().verify_at(KEY, 200),
            Err(DomainError::TokenExpired {
                expires_at_ms: 200,
                now_ms: 200
            })
        ));
    }

    #[test]
    fn invalid_lifetime_and_future_issue_are_rejected() {
        let mut invalid = token();
        invalid.issued_at_ms = invalid.expires_at_ms;
        assert!(matches!(
            invalid.validate_claims(),
            Err(DomainError::InvalidToken(_))
        ));
        assert!(matches!(
            token().verify_at(KEY, 99),
            Err(DomainError::InvalidToken(_))
        ));
    }
}
