use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::{Digest, DomainError};

const MAX_NAME_BYTES: usize = 128;

fn invalid_name_reason(value: &str) -> Option<&'static str> {
    if value.is_empty() {
        return Some("must not be empty");
    }
    if value.len() > MAX_NAME_BYTES {
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

fn invalid_scalar(kind: &'static str, value: impl ToString, reason: &'static str) -> DomainError {
    DomainError::InvalidId {
        kind,
        value: value.to_string(),
        reason,
    }
}

macro_rules! define_name_id {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
            #[serde(transparent)]
            pub struct $name(String);

            impl $name {
                pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                    let value = value.into();
                    if let Some(reason) = invalid_name_reason(&value) {
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

define_name_id!(AtlasId, TokenizerId, EmbeddingModelId);

macro_rules! define_digest_id {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!(stringify!($name), " backed by a canonical BLAKE3 digest.")]
            #[derive(
                Clone,
                Copy,
                Debug,
                Deserialize,
                Eq,
                Hash,
                Ord,
                PartialEq,
                PartialOrd,
                Serialize,
            )]
            #[serde(transparent)]
            pub struct $name(Digest);

            impl $name {
                pub const fn new(digest: Digest) -> Self {
                    Self(digest)
                }

                pub fn parse(value: &str) -> Result<Self, DomainError> {
                    Digest::parse(value).map(Self)
                }

                pub const fn as_digest(&self) -> &Digest {
                    &self.0
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    self.0.fmt(formatter)
                }
            }

            impl FromStr for $name {
                type Err = DomainError;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    Self::parse(value)
                }
            }
        )+
    };
}

define_digest_id!(
    KnowledgeItemId,
    KnowledgeChunkId,
    IndexGenerationId,
    CapabilityListingDigest,
);

macro_rules! define_uuid_id {
    ($($name:ident),+ $(,)?) => {
        $(
            #[doc = concat!("Stable, authority-supplied, non-content UUID identifier for ", stringify!($name), ".")]
            #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
            #[serde(transparent)]
            pub struct $name(Uuid);

            impl $name {
                pub const fn new(uuid: Uuid) -> Self {
                    Self(uuid)
                }

                pub fn parse(value: &str) -> Result<Self, DomainError> {
                    let parsed = Uuid::parse_str(value).map_err(|_| {
                        invalid_scalar(stringify!($name), value, "must be a canonical UUID")
                    })?;
                    if parsed.to_string() != value {
                        return Err(invalid_scalar(
                            stringify!($name),
                            value,
                            "must be a lowercase hyphenated UUID",
                        ));
                    }
                    Ok(Self(parsed))
                }

                pub const fn as_uuid(&self) -> &Uuid {
                    &self.0
                }

                pub const fn into_uuid(self) -> Uuid {
                    self.0
                }
            }

            impl fmt::Display for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    self.0.fmt(formatter)
                }
            }

            impl<'de> Deserialize<'de> for $name {
                fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    let value = String::deserialize(deserializer)?;
                    Self::parse(&value).map_err(serde::de::Error::custom)
                }
            }

            impl FromStr for $name {
                type Err = DomainError;

                fn from_str(value: &str) -> Result<Self, Self::Err> {
                    Self::parse(value)
                }
            }
        )+
    };
}

define_uuid_id!(KnowledgeFactId);

/// Quantized retrieval relevance in integer millionths.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RelevanceScore(u32);

impl RelevanceScore {
    pub const ZERO: Self = Self(0);
    pub const MAX: u32 = 1_000_000;

    pub fn new(value: u32) -> Result<Self, DomainError> {
        if value > Self::MAX {
            return Err(invalid_scalar(
                "RelevanceScore",
                value,
                "must be between 0 and 1,000,000 inclusive",
            ));
        }
        Ok(Self(value))
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let value = value.parse().map_err(|_| {
            invalid_scalar(
                "RelevanceScore",
                value,
                "must be an unsigned 32-bit integer",
            )
        })?;
        Self::new(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for RelevanceScore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for RelevanceScore {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<u32> for RelevanceScore {
    type Error = DomainError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for RelevanceScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{AtlasId, IndexGenerationId, KnowledgeFactId, KnowledgeItemId, RelevanceScore};
    use crate::Digest;

    #[test]
    fn validated_name_ids_roundtrip() {
        let atlas = AtlasId::new("atlas.core-v1").unwrap();
        assert_eq!(atlas.as_str(), "atlas.core-v1");
        assert_eq!(atlas.to_string().parse::<AtlasId>().unwrap(), atlas);
        assert_eq!(
            serde_json::from_str::<AtlasId>(&serde_json::to_string(&atlas).unwrap()).unwrap(),
            atlas
        );

        for invalid in ["", ".atlas", "atlas/core", "atlás"] {
            assert!(AtlasId::new(invalid).is_err());
        }
    }

    #[test]
    fn digest_ids_use_digest_text_and_serde() {
        let digest = Digest::hash(b"index generation");
        let id = IndexGenerationId::new(digest);
        assert_eq!(id.to_string(), digest.to_string());
        assert_eq!(id.to_string().parse::<IndexGenerationId>().unwrap(), id);
        assert_eq!(
            serde_json::from_str::<IndexGenerationId>(&serde_json::to_string(&id).unwrap())
                .unwrap(),
            id
        );
    }

    #[test]
    fn uuid_ids_only_wrap_or_parse_supplied_uuid() {
        let uuid = Uuid::parse_str("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9").unwrap();
        let fact_id = KnowledgeFactId::new(uuid);
        assert_eq!(fact_id.as_uuid(), &uuid);
        assert_eq!(
            fact_id.to_string().parse::<KnowledgeFactId>().unwrap(),
            fact_id
        );
        assert!(KnowledgeFactId::parse("not-a-uuid").is_err());
        assert!(KnowledgeFactId::parse("8F9C2EE3-85EC-46E9-A43A-A2CD6048C1E9").is_err());
        assert!(KnowledgeFactId::parse("8f9c2ee385ec46e9a43aa2cd6048c1e9").is_err());
        assert!(serde_json::from_str::<KnowledgeFactId>(
            "\"8F9C2EE3-85EC-46E9-A43A-A2CD6048C1E9\""
        )
        .is_err());

        let item_id = KnowledgeItemId::new(Digest::hash(b"same-looking-fact"));
        assert!(
            serde_json::to_value(fact_id).unwrap().is_string(),
            "fact identity is a stable UUID"
        );
        assert_ne!(
            fact_id.to_string(),
            item_id.to_string(),
            "fact identity must not collapse into immutable content identity"
        );
    }

    #[test]
    fn relevance_score_enforces_integer_millionths() {
        assert_eq!(RelevanceScore::new(0).unwrap().get(), 0);
        assert_eq!(
            RelevanceScore::new(RelevanceScore::MAX).unwrap().get(),
            1_000_000
        );
        assert!(RelevanceScore::new(1_000_001).is_err());
        assert!(serde_json::from_str::<RelevanceScore>("1000001").is_err());
        assert_eq!(
            serde_json::from_str::<RelevanceScore>("250000")
                .unwrap()
                .get(),
            250_000
        );
    }
}
