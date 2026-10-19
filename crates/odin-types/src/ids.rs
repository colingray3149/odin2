//! Validate IDs at construction so downstream code can use them as safe tokens.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash::{HashError, HashHex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    Empty(&'static str),
    TooLong {
        kind: &'static str,
        length: usize,
        ceiling: usize,
    },
    BadChar {
        kind: &'static str,
        ch: char,
    },
    BadShape {
        kind: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdError::Empty(k) => write!(f, "{k} must be non-empty"),
            IdError::TooLong {
                kind,
                length,
                ceiling,
            } => {
                write!(f, "{kind} length {length} exceeds ceiling {ceiling}")
            }
            IdError::BadChar { kind, ch } => {
                write!(f, "{kind} contains forbidden character {ch:?}")
            }
            IdError::BadShape { kind, reason } => {
                write!(f, "{kind} shape rejected: {reason}")
            }
        }
    }
}

impl std::error::Error for IdError {}

pub trait SafeId {
    const KIND: &'static str;
    const MAX_LEN: usize;
    fn as_str(&self) -> &str;

    fn validate(s: &str) -> Result<(), IdError> {
        if s.is_empty() {
            return Err(IdError::Empty(Self::KIND));
        }
        if s.len() > Self::MAX_LEN {
            return Err(IdError::TooLong {
                kind: Self::KIND,
                length: s.len(),
                ceiling: Self::MAX_LEN,
            });
        }
        for ch in s.chars() {
            if !is_safe(ch) {
                return Err(IdError::BadChar {
                    kind: Self::KIND,
                    ch,
                });
            }
        }
        Ok(())
    }
}

pub fn is_safe(ch: char) -> bool {
    matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | ':')
}

macro_rules! id_newtype {
    ($name:ident, $kind:literal, $max:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(compact_str::CompactString);

        impl $name {
            pub fn new(s: &str) -> Result<Self, IdError> {
                <Self as SafeId>::validate(s)?;
                Ok(Self(compact_str::CompactString::new(s)))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl SafeId for $name {
            const KIND: &'static str = $kind;
            const MAX_LEN: usize = $max;
            fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl std::ops::Deref for $name {
            type Target = str;
            fn deref(&self) -> &str {
                self.0.as_str()
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(&value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0.to_string()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0.as_str())
            }
        }
    };
}

id_newtype!(ToolId, "ToolId", 128);
id_newtype!(CapsuleId, "CapsuleId", 128);
id_newtype!(OperationId, "OperationId", 128);
id_newtype!(CapsuleLeaseId, "CapsuleLeaseId", 128);
id_newtype!(WorkerId, "WorkerId", 128);
/// Use an even hex length so correlation IDs decode to whole bytes.
pub const CORRELATION_ID_HEX_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CorrelationId([u8; 32]);

impl CorrelationId {
    pub fn new(s: &str) -> Result<Self, IdError> {
        if s.is_empty() {
            return Err(IdError::Empty("CorrelationId"));
        }
        if s.len() != CORRELATION_ID_HEX_LEN {
            return Err(IdError::BadShape {
                kind: "CorrelationId",
                reason: "must be exactly 32 lowercase hex characters",
            });
        }
        for b in s.as_bytes() {
            if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
                return Err(IdError::BadChar {
                    kind: "CorrelationId",
                    ch: *b as char,
                });
            }
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(s.as_bytes());
        Ok(Self(buf))
    }

    #[inline(always)]
    pub fn as_str(&self) -> &str {
        match std::str::from_utf8(&self.0) {
            Ok(s) => s,
            Err(_) => unreachable!("CorrelationId bytes are verified ASCII"),
        }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::ops::Deref for CorrelationId {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl TryFrom<String> for CorrelationId {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<CorrelationId> for String {
    fn from(value: CorrelationId) -> Self {
        value.as_str().to_owned()
    }
}

impl AsRef<str> for CorrelationId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub const PREDECESSOR_HASH_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PredecessorHash(String);

impl PredecessorHash {
    pub fn new(s: &str) -> Result<Self, IdError> {
        if s.is_empty() {
            return Err(IdError::Empty("PredecessorHash"));
        }
        match HashHex::from_hex(s) {
            Ok(hex) => Ok(Self(hex.as_str().to_owned())),
            Err(HashError::BadChar(ch)) => Err(IdError::BadChar {
                kind: "PredecessorHash",
                ch,
            }),
            Err(HashError::WrongLength { .. } | HashError::OddLength(_)) => {
                Err(IdError::BadShape {
                    kind: "PredecessorHash",
                    reason: "must be exactly 64 lowercase hex characters",
                })
            }
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PredecessorHash {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<PredecessorHash> for String {
    fn from(value: PredecessorHash) -> Self {
        value.0
    }
}

impl AsRef<str> for PredecessorHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PredecessorHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod canonical_operation_ids {
    use super::*;

    #[test]
    fn operation_ids_accept_only_their_canonical_shape() {
        let canonical = "op-0123456789abcdef0123456789abcdef";
        let id = OperationId::new(canonical).expect("canonical operation id");
        assert_eq!(id.as_str(), canonical);
        let corrupted = OperationId::new("op-UPPER@case");
        assert!(
            corrupted.is_err(),
            "operation ids reject characters outside the safe set"
        );
        let empty = OperationId::new("");
        assert!(empty.is_err(), "operation ids reject the empty string");
    }

    #[test]
    fn correlation_ids_are_fixed_length_lowercase_hex() {
        let canonical = "0123456789abcdef0123456789abcdef";
        let id = CorrelationId::new(canonical).expect("canonical correlation id");
        assert_eq!(id.as_str(), canonical);
        assert_eq!(canonical.len(), CORRELATION_ID_HEX_LEN);
        let short = CorrelationId::new("0123456789abcdef");
        assert!(
            short.is_err(),
            "correlation ids reject the wrong fixed length"
        );
        let non_hex = CorrelationId::new("0123456789 abcdef0123456789abcdef");
        assert!(
            non_hex.is_err(),
            "correlation ids reject non-hex characters"
        );
    }

    #[test]
    fn capsule_lease_and_worker_ids_share_the_single_safe_id_owner() {
        let lease = CapsuleLeaseId::new("lease-0123456789abcdef").expect("canonical lease id");
        assert_eq!(lease.as_str(), "lease-0123456789abcdef");
        let worker = WorkerId::new("worker-0123456789abcdef").expect("canonical worker id");
        assert_eq!(worker.as_str(), "worker-0123456789abcdef");
        assert!(
            CapsuleLeaseId::new("").is_err(),
            "lease ids reject emptiness"
        );
        assert!(
            WorkerId::new("worker space").is_err(),
            "worker ids reject spaces"
        );
        let overflowing = "x".repeat(129);
        assert!(
            CapsuleLeaseId::new(&overflowing).is_err(),
            "lease ids enforce their ceiling"
        );
        assert!(
            WorkerId::new(&overflowing).is_err(),
            "worker ids enforce their ceiling"
        );
    }

    #[test]
    fn operation_id_identities_survive_the_shared_owner_conversions() {
        let operation = OperationId::try_from("op-round-trip".to_owned()).unwrap();
        let correlation =
            CorrelationId::try_from("0123456789abcdef0123456789abcdef".to_owned()).unwrap();
        let lease = CapsuleLeaseId::try_from("lease-round-trip".to_owned()).unwrap();
        let worker = WorkerId::try_from("worker-round-trip".to_owned()).unwrap();
        assert_eq!(operation.as_str(), "op-round-trip");
        assert_eq!(correlation.as_str(), "0123456789abcdef0123456789abcdef");
        assert_eq!(lease.as_str(), "lease-round-trip");
        assert_eq!(worker.as_str(), "worker-round-trip");
        assert_eq!(operation.to_string(), "op-round-trip");
        assert_eq!(correlation.to_string(), "0123456789abcdef0123456789abcdef");
        assert_eq!(lease.to_string(), "lease-round-trip");
        assert_eq!(worker.to_string(), "worker-round-trip");
    }
}
