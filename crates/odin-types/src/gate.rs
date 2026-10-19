//! Typed reason codes.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Use the stable code as a key, never the human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReasonCode {
    pub category: ReasonCategory,
    pub code: String,
    pub message: String,
}

impl ReasonCode {
    pub fn new(
        category: ReasonCategory,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            category,
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCategory {
    DuplicateKey,
    UnknownField,
    MalformedId,
    HashMismatch,
    ByteCeiling,
    UnparseableShape,
    TrailingData,
    MaxDepth,
    NonFiniteNumber,
    Other,
}

impl ReasonCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ReasonCategory::DuplicateKey => "duplicate_key",
            ReasonCategory::UnknownField => "unknown_field",
            ReasonCategory::MalformedId => "malformed_id",
            ReasonCategory::HashMismatch => "hash_mismatch",
            ReasonCategory::ByteCeiling => "byte_ceiling",
            ReasonCategory::UnparseableShape => "unparseable_shape",
            ReasonCategory::TrailingData => "trailing_data",
            ReasonCategory::MaxDepth => "max_depth",
            ReasonCategory::NonFiniteNumber => "non_finite_number",
            ReasonCategory::Other => "other",
        }
    }
}

impl fmt::Display for ReasonCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ReasonCode {
    pub fn duplicate_key(detail: impl fmt::Display) -> Self {
        Self::new(
            ReasonCategory::DuplicateKey,
            "json.duplicate_key",
            format!("object contains duplicate key: {detail}"),
        )
    }

    pub fn byte_ceiling(size: usize, ceiling: usize) -> Self {
        Self::new(
            ReasonCategory::ByteCeiling,
            "json.byte_ceiling",
            format!("payload size {size} exceeds ceiling {ceiling}"),
        )
    }
}
