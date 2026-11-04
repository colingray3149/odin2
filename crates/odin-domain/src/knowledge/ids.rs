use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::{Digest, DomainError};

fn invalid_scalar(
    kind: &'static str,
    value: impl ToString,
    reason: impl Into<String>,
) -> DomainError {
    DomainError::InvalidId {
        kind,
        value: value.to_string(),
        reason: reason.into(),
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
                    if let Some(reason) = crate::ids::invalid_id_reason(&value) {
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
                    let parsed = Uuid::parse_str(value).map_err(|error| {
                        invalid_scalar(
                            stringify!($name),
                            value,
                            format!("must be a canonical UUID: {error}"),
                        )
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
        let value = value.parse().map_err(|error| {
            invalid_scalar(
                "RelevanceScore",
                value,
                format!("must be an unsigned 32-bit integer: {error}"),
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

    use super::RelevanceScore;

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
