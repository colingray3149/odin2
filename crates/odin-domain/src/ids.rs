use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::DomainError;

const MAX_ID_BYTES: usize = 128;
const DIGEST_PREFIX: &str = "blake3:";
const DIGEST_HEX_BYTES: usize = 64;

fn invalid_id_reason(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("must not be empty");
    }
    if value.len() > MAX_ID_BYTES {
        return Some("must not exceed 128 bytes");
    }

    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Some("must start with an ASCII alphanumeric character");
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Some("must contain only ASCII alphanumeric characters or '.', '_', ':', and '-'");
    }

    None
}

macro_rules! define_id {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
            #[serde(transparent)]
            pub struct $name(String);

            impl $name {
                pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                    let value = value.into();
                    if let Some(reason) = invalid_id_reason(&value) {
                        return Err(DomainError::InvalidId {
                            kind: stringify!($name),
                            value,
                            reason,
                        });
                    }
                    Ok(Self(value))
                }

                pub fn parse(value: &str) -> Result<Self, DomainError> {
                    Self::new(value)
                }

                pub fn from_parts(
                    prefix: &str,
                    now_ms: u64,
                    entropy: impl fmt::Display,
                ) -> Result<Self, DomainError> {
                    Self::new(format!("{prefix}:{now_ms}:{entropy}"))
                }

                pub fn as_str(&self) -> &str {
                    &self.0
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(&self.0)
                }
            }

            impl FromStr for $name {
                type Err = DomainError;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    Self::parse(value)
                }
            }

            impl<'de> Deserialize<'de> for $name {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: Deserializer<'de>,
                {
                    let value = String::deserialize(deserializer)?;
                    Self::new(value).map_err(serde::de::Error::custom)
                }
            }
        )+
    };
}

define_id!(
    SeatId,
    ProjectId,
    LaneId,
    RunId,
    AttemptId,
    ArmId,
    NodeId,
    CapabilityId,
    SliceId,
    ContainerId,
    HostId,
    CommandId,
    EventId,
    ApprovalId,
    LeaseId,
    ArtifactId,
    ProviderId,
    IncidentId,
    PlanId,
    TodoId,
    CheckpointId,
    TaskId,
    SessionId,
    TurnId,
    SeatTokenId,
);

/// A BLAKE3 digest serialized as `blake3:` followed by 64 lowercase hex digits.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest([u8; 32]);

impl Digest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn hash(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let encoded = value
            .strip_prefix(DIGEST_PREFIX)
            .ok_or_else(|| invalid_digest(value, "must start with 'blake3:'"))?;
        if encoded.len() != DIGEST_HEX_BYTES {
            return Err(invalid_digest(
                value,
                "must contain exactly 64 hexadecimal digits",
            ));
        }
        if !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(invalid_digest(
                value,
                "must use lowercase hexadecimal digits",
            ));
        }

        let encoded = encoded.as_bytes();
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = (hex_value(encoded[offset]) << 4) | hex_value(encoded[offset + 1]);
        }
        Ok(Self(bytes))
    }
}

fn invalid_digest(value: &str, reason: &'static str) -> DomainError {
    DomainError::InvalidDigest {
        value: value.to_owned(),
        reason,
    }
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(DIGEST_PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Digest {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, DomainError, SeatId};

    #[test]
    fn id_validation_and_roundtrip() {
        let id = SeatId::new("seat.alpha_1:primary-2").unwrap();
        assert_eq!(id.as_str(), "seat.alpha_1:primary-2");
        assert_eq!(id.to_string().parse::<SeatId>().unwrap(), id);
        assert_eq!(
            serde_json::from_str::<SeatId>(&serde_json::to_string(&id).unwrap()).unwrap(),
            id
        );

        for invalid in ["", "_seat", "seat/one", "séat"] {
            assert!(matches!(
                SeatId::new(invalid),
                Err(DomainError::InvalidId { .. })
            ));
        }
        assert!(SeatId::new("a".repeat(129)).is_err());
    }

    #[test]
    fn id_from_parts_is_deterministic() {
        let first = SeatId::from_parts("seat", 1_725_000_000_123, "a1b2").unwrap();
        let second = SeatId::from_parts("seat", 1_725_000_000_123, "a1b2").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.as_str(), "seat:1725000000123:a1b2");
    }

    #[test]
    fn digest_parsing_is_canonical() {
        let digest = Digest::hash(b"odin");
        let encoded = digest.to_string();
        assert_eq!(encoded.len(), 71);
        assert_eq!(encoded.parse::<Digest>().unwrap(), digest);
        assert_eq!(
            serde_json::from_str::<Digest>(&serde_json::to_string(&digest).unwrap()).unwrap(),
            digest
        );

        assert!(Digest::parse(&encoded.to_uppercase()).is_err());
        assert!(Digest::parse(encoded.trim_start_matches("blake3:")).is_err());
        assert!(Digest::parse("blake3:00").is_err());
    }
}
