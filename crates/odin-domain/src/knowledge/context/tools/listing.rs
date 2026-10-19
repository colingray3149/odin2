//! Immutable, seat-token-bound capability listings.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, UtcOffset};

use crate::huginn::ids::LiveSessionId;
use crate::knowledge::ids::CapabilityListingDigest;
use crate::{Digest, DomainError, SeatId, SeatTokenId, SliceId};

use super::ToolCapability;

fn invalid(reason: impl Into<String>) -> DomainError {
    DomainError::InvalidScope(format!("capability listing: {}", reason.into()))
}

/// The public claims whose canonical representation determines a listing digest.
///
/// Only the seat-token identifier is present: token material and signatures are deliberately
/// excluded. Expiry is bound so it cannot be extended independently of the listing identity.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityListingDigestMaterial<'a> {
    pub seat_token_id: &'a SeatTokenId,
    pub seat_id: &'a SeatId,
    pub slice_id: &'a SliceId,
    pub session_id: &'a LiveSessionId,
    pub policy_digest: &'a Digest,
    pub expires_at: OffsetDateTime,
    pub tools: &'a [ToolCapability],
}

/// One exact, expiring set of tools resolved for a seat, slice, session, and seat token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityListing {
    pub seat_id: SeatId,
    pub slice_id: SliceId,
    pub session_id: LiveSessionId,
    pub seat_token_id: SeatTokenId,
    pub policy_digest: Digest,
    pub expires_at: OffsetDateTime,
    pub tools: Vec<ToolCapability>,
    pub digest: CapabilityListingDigest,
}

pub struct CapabilityListingInit {
    pub seat_id: SeatId,
    pub slice_id: SliceId,
    pub session_id: LiveSessionId,
    pub seat_token_id: SeatTokenId,
    pub policy_digest: Digest,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub tools: Vec<ToolCapability>,
}

impl CapabilityListing {
    pub fn new(init: CapabilityListingInit) -> Result<Self, DomainError> {
        let CapabilityListingInit {
            seat_id,
            session_id,
            slice_id,
            seat_token_id,
            policy_digest,
            issued_at,
            expires_at,
            mut tools,
        } = init;
        if expires_at <= issued_at {
            return Err(invalid("expiry must follow issuance"));
        }

        tools.sort_by(compare_tools);
        validate_ordered_tools(&tools)?;
        let expires_at = expires_at.to_offset(UtcOffset::UTC);
        let digest = digest_for(
            &seat_token_id,
            &seat_id,
            &slice_id,
            &session_id,
            &policy_digest,
            expires_at,
            &tools,
        )?;

        Ok(Self {
            seat_id,
            slice_id,
            session_id,
            seat_token_id,
            policy_digest,
            expires_at,
            tools,
            digest,
        })
    }

    /// Revalidates descriptor order, uniqueness, and the exact stored digest.
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_ordered_tools(&self.tools)?;
        let expected = CapabilityListingDigest::new(Digest::hash(&self.digest_material_bytes()?));
        if self.digest != expected {
            return Err(invalid("digest does not match the bound listing material"));
        }
        Ok(())
    }

    pub fn digest_material(&self) -> CapabilityListingDigestMaterial<'_> {
        CapabilityListingDigestMaterial {
            seat_token_id: &self.seat_token_id,
            seat_id: &self.seat_id,
            slice_id: &self.slice_id,
            session_id: &self.session_id,
            policy_digest: &self.policy_digest,
            expires_at: self.expires_at.to_offset(UtcOffset::UTC),
            tools: &self.tools,
        }
    }

    /// Returns the recursively key-ordered JSON value used to derive the digest bytes.
    pub fn digest_material_value(&self) -> Result<Value, DomainError> {
        serde_json::to_value(self.digest_material())
            .map_err(|error| invalid(format!("digest material cannot be encoded: {error}")))
    }

    pub fn digest_material_bytes(&self) -> Result<Vec<u8>, DomainError> {
        serde_json::to_vec(&self.digest_material_value()?)
            .map_err(|error| invalid(format!("digest material cannot be encoded: {error}")))
    }
}

fn compare_tools(left: &ToolCapability, right: &ToolCapability) -> Ordering {
    left.tool_name
        .cmp(&right.tool_name)
        .then_with(|| left.capability_id.cmp(&right.capability_id))
}

fn validate_ordered_tools(tools: &[ToolCapability]) -> Result<(), DomainError> {
    for tool in tools {
        tool.validate()?;
    }
    for pair in tools.windows(2) {
        match compare_tools(&pair[0], &pair[1]) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(invalid("tool name and capability ID pairs must be unique"));
            }
            Ordering::Greater => {
                return Err(invalid(
                    "tools must be ordered by tool name and capability ID",
                ));
            }
        }
    }
    Ok(())
}

fn digest_for(
    seat_token_id: &SeatTokenId,
    seat_id: &SeatId,
    slice_id: &SliceId,
    session_id: &LiveSessionId,
    policy_digest: &Digest,
    expires_at: OffsetDateTime,
    tools: &[ToolCapability],
) -> Result<CapabilityListingDigest, DomainError> {
    let material = CapabilityListingDigestMaterial {
        seat_token_id,
        seat_id,
        slice_id,
        session_id,
        policy_digest,
        expires_at,
        tools,
    };
    let value = serde_json::to_value(material)
        .map_err(|error| invalid(format!("digest material cannot be encoded: {error}")))?;
    let bytes = serde_json::to_vec(&value)
        .map_err(|error| invalid(format!("digest material cannot be encoded: {error}")))?;
    Ok(CapabilityListingDigest::new(Digest::hash(&bytes)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::Duration;

    use super::*;
    use crate::knowledge::context::{ToolCapabilityInit, ToolName, ToolSchema};
    use crate::CapabilityId;

    fn tool(name: &str, capability: &str) -> ToolCapability {
        let schema = ToolSchema::from_value(json!({"type": "object"})).unwrap();
        let schema_digest = schema.digest();
        ToolCapability::new(ToolCapabilityInit {
            capability_id: CapabilityId::new(capability).unwrap(),
            tool_name: ToolName::new(name).unwrap(),
            description: format!("{name} tool"),
            input_schema: schema,
            schema_digest,
            resource_constraints: Vec::new(),
        })
        .unwrap()
    }

    fn listing(tools: Vec<ToolCapability>) -> Result<CapabilityListing, DomainError> {
        let issued_at = OffsetDateTime::UNIX_EPOCH;
        CapabilityListing::new(CapabilityListingInit {
            seat_id: SeatId::new("seat.one").unwrap(),
            slice_id: SliceId::new("slice.one").unwrap(),
            session_id: LiveSessionId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
            seat_token_id: SeatTokenId::new("token.one").unwrap(),
            policy_digest: Digest::hash(b"policy"),
            issued_at,
            expires_at: issued_at + Duration::minutes(5),
            tools,
        })
    }

    #[test]
    fn constructor_orders_tools_and_digest_material_deterministically() {
        let a = listing(vec![tool("zeta", "cap.z"), tool("alpha", "cap.a")]).unwrap();
        let b = listing(vec![tool("alpha", "cap.a"), tool("zeta", "cap.z")]).unwrap();

        assert_eq!(a.tools[0].tool_name.as_str(), "alpha");
        assert_eq!(a.tools[1].tool_name.as_str(), "zeta");
        assert_eq!(
            a.digest_material_value().unwrap(),
            b.digest_material_value().unwrap()
        );
        assert_eq!(
            a.digest_material_bytes().unwrap(),
            b.digest_material_bytes().unwrap()
        );
        assert_eq!(a.digest, b.digest);
        assert!(a.validate().is_ok());
    }

    #[test]
    fn duplicate_descriptor_keys_are_rejected() {
        let duplicate = tool("same", "cap.same");
        assert!(listing(vec![duplicate.clone(), duplicate]).is_err());
    }

    #[test]
    fn listing_must_be_live_when_issued() {
        let at = OffsetDateTime::UNIX_EPOCH;
        let result = CapabilityListing::new(CapabilityListingInit {
            seat_id: SeatId::new("seat.one").unwrap(),
            slice_id: SliceId::new("slice.one").unwrap(),
            session_id: LiveSessionId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
            seat_token_id: SeatTokenId::new("token.one").unwrap(),
            policy_digest: Digest::hash(b"policy"),
            issued_at: at,
            expires_at: at,
            tools: Vec::new(),
        });
        assert!(result.is_err());
    }
}
