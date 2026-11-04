use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use odin_types::MAX_ID_BYTES;

use crate::DomainError;

const DIGEST_PREFIX: &str = "blake3:";
const DIGEST_HEX_BYTES: usize = 64;

/// Why `value` is not a safe identifier, if it is not: 1..=`MAX_ID_BYTES` bytes of ASCII
/// alphanumerics and `.`, `_`, `:`, `-`, starting alphanumeric. Every string id shares it.
pub(crate) fn invalid_id_reason(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("must not be empty".to_owned());
    }
    if value.len() > MAX_ID_BYTES {
        return Some(format!("must not exceed {MAX_ID_BYTES} bytes"));
    }

    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Some("must start with an ASCII alphanumeric character".to_owned());
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Some(
            "must contain only ASCII alphanumeric characters or '.', '_', ':', and '-'".to_owned(),
        );
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
                            reason: reason.to_owned(),
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

    /// The 64 lowercase hex digits, without the `blake3:` prefix.
    pub fn hex(&self) -> String {
        odin_types::hash::hex_encode(&self.0)
    }

    /// The digest of `value`'s compact JSON encoding, the same bytes as
    /// `serde_json::to_vec`, streamed into the hasher.
    pub fn hash_json(value: &serde_json::Value) -> Self {
        let mut hasher = blake3::Hasher::new();
        serde_json::to_writer(&mut hasher, value)
            .expect("serializing serde_json::Value into blake3::Hasher cannot fail");
        Self(*hasher.finalize().as_bytes())
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

        let bytes = odin_types::hash::hex_decode(encoded)
            .ok()
            .and_then(|decoded| <[u8; 32]>::try_from(decoded).ok())
            .ok_or_else(|| invalid_digest(value, "must contain exactly 64 hexadecimal digits"))?;
        Ok(Self(bytes))
    }
}

fn invalid_digest(value: &str, reason: &'static str) -> DomainError {
    DomainError::InvalidDigest {
        value: value.to_owned(),
        reason,
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
