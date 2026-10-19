//! Decode errors and decoding options.

use std::fmt;

use serde::{Deserialize, Serialize};

use odin_types::gate::ReasonCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodeOptions {
    /// Maximum input size, in bytes. Set to `usize::MAX` to disable.
    pub byte_ceiling: usize,
    /// Maximum recursion depth for objects/arrays. 0 disables the check.
    pub max_depth: usize,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            byte_ceiling: 1024 * 1024,
            max_depth: 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecodeError {
    Empty,
    ByteCeiling {
        size: usize,
        ceiling: usize,
    },
    InvalidNumber {
        offset: usize,
        source: String,
    },
    InvalidEscape {
        offset: usize,
        byte: u8,
    },
    InvalidUnicode {
        offset: usize,
    },
    InvalidLiteral {
        offset: usize,
        source: String,
    },
    UnexpectedEof,
    UnexpectedToken {
        offset: usize,
        found: String,
        expected: &'static str,
    },
    TrailingData {
        offset: usize,
    },
    NonFiniteNumber {
        offset: usize,
    },
    DuplicateKey {
        key: String,
        first_offset: usize,
        second_offset: usize,
    },
    MaxDepthExceeded {
        depth: usize,
        offset: usize,
    },
    /// Preserve the underlying serde failure category, such as UnknownField.
    TypedMismatch {
        category: odin_types::gate::ReasonCategory,
        code: &'static str,
        message: String,
    },
}

impl DecodeError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            DecodeError::Empty => ReasonCode::new(
                odin_types::gate::ReasonCategory::UnparseableShape,
                "json.empty",
                "input is empty",
            ),
            DecodeError::ByteCeiling { size, ceiling } => ReasonCode::byte_ceiling(*size, *ceiling),
            DecodeError::InvalidNumber { offset, source } => ReasonCode::new(
                odin_types::gate::ReasonCategory::UnparseableShape,
                "json.invalid_number",
                format!("at offset {offset}: {source}"),
            ),
            DecodeError::InvalidEscape { offset, byte } => ReasonCode::new(
                odin_types::gate::ReasonCategory::UnparseableShape,
                "json.invalid_escape",
                format!("at offset {offset}: bad escape {byte:#04x}"),
            ),
            DecodeError::InvalidUnicode { offset } => ReasonCode::new(
                odin_types::gate::ReasonCategory::UnparseableShape,
                "json.invalid_unicode",
                format!("at offset {offset}: bad \\u escape"),
            ),
            DecodeError::InvalidLiteral { offset, source } => ReasonCode::new(
                odin_types::gate::ReasonCategory::UnparseableShape,
                "json.invalid_literal",
                format!("at offset {offset}: {source}"),
            ),
            DecodeError::UnexpectedEof => ReasonCode::new(
                odin_types::gate::ReasonCategory::UnparseableShape,
                "json.unexpected_eof",
                "input ended before value was complete",
            ),
            DecodeError::UnexpectedToken {
                offset,
                found,
                expected,
            } => ReasonCode::new(
                odin_types::gate::ReasonCategory::UnparseableShape,
                "json.unexpected_token",
                format!("at offset {offset}: found {found}, expected {expected}"),
            ),
            DecodeError::TrailingData { offset } => ReasonCode::new(
                odin_types::gate::ReasonCategory::TrailingData,
                "json.trailing_data",
                format!("non-whitespace data at offset {offset} after top-level value"),
            ),
            DecodeError::NonFiniteNumber { offset } => ReasonCode::new(
                odin_types::gate::ReasonCategory::NonFiniteNumber,
                "json.non_finite_number",
                format!("at offset {offset}: NaN or infinity is not allowed"),
            ),
            DecodeError::DuplicateKey {
                key, second_offset, ..
            } => ReasonCode::duplicate_key(format!(
                "{key:?} (second occurrence at offset {second_offset})"
            )),
            DecodeError::MaxDepthExceeded { depth, offset } => ReasonCode::new(
                odin_types::gate::ReasonCategory::MaxDepth,
                "json.max_depth",
                format!("at offset {offset}: depth {depth} exceeds limit"),
            ),
            DecodeError::TypedMismatch {
                category,
                code,
                message,
            } => ReasonCode::new(*category, *code, message.clone()),
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason().message)
    }
}

impl std::error::Error for DecodeError {}
