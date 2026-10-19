//! Versioned canonical CBOR and redacted JSON debug codecs.

use std::num::NonZeroUsize;

use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = odin_domain::huginn::protocol::HUGINN_PROTOCOL_VERSION;
const MAX_DEBUG_TEXT_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodecLimits {
    pub max_frame_bytes: usize,
    pub max_depth: u8,
    pub max_container_items: usize,
    pub max_text_bytes: usize,
}

impl CodecLimits {
    pub const fn conservative() -> Self {
        Self {
            max_frame_bytes: 16 * 1_024 * 1_024,
            max_depth: 32,
            max_container_items: 65_536,
            max_text_bytes: 4 * 1_024 * 1_024,
        }
    }

    pub const fn from_max_frame_bytes(max_frame_bytes: NonZeroUsize) -> Self {
        Self {
            max_frame_bytes: max_frame_bytes.get(),
            ..Self::conservative()
        }
    }
}

impl Default for CodecLimits {
    fn default() -> Self {
        Self::conservative()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CodecError {
    #[error("protocol version {received} is unsupported (supported: {supported})")]
    UnsupportedVersion { received: u64, supported: u16 },
    #[error("frame is not canonical CBOR: {code}")]
    Malformed { code: &'static str },
    #[error("frame exceeds declared limit: {limit}")]
    LimitExceeded { limit: &'static str },
    #[error("unknown protocol kind {kind:?}")]
    UnknownKind { kind: String },
    #[error("codec failure: {0}")]
    Message(String),
}

impl CodecError {
    pub fn into_protocol_error(self) -> odin_domain::huginn::protocol::HuginnProtocolError {
        use odin_domain::huginn::protocol::HuginnProtocolError;
        match self {
            Self::UnsupportedVersion {
                received,
                supported,
            } => HuginnProtocolError::UnsupportedVersion {
                received: received.min(u64::from(u16::MAX)) as u16,
                supported,
            },
            Self::LimitExceeded { limit } => HuginnProtocolError::ResourceLimit {
                limit: limit.to_owned(),
            },
            Self::UnknownKind { kind } => HuginnProtocolError::InvalidRequest {
                code: "unknownKind".to_owned(),
                message: kind,
            },
            Self::Malformed { code } => HuginnProtocolError::InvalidRequest {
                code: "malformedFrame".to_owned(),
                message: code.to_owned(),
            },
            Self::Message(message) => HuginnProtocolError::InvalidRequest {
                code: "malformedFrame".to_owned(),
                message,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Versioned<T> {
    pub version: u16,
    pub value: T,
}

impl<T> Versioned<T> {
    pub const fn new(value: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            value,
        }
    }
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    encode_frame(value, &CodecLimits::default())
}

pub fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<T, CodecError> {
    decode_frame(frame, &CodecLimits::default()).map(|versioned| versioned.value)
}

pub fn encode_frame<T: Serialize>(value: &T, limits: &CodecLimits) -> Result<Vec<u8>, CodecError> {
    let frame = encode_canonical(&(PROTOCOL_VERSION, value), limits)?;
    validate_frame(&frame, limits)?;
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(
    frame: &[u8],
    limits: &CodecLimits,
) -> Result<Versioned<T>, CodecError> {
    validate_frame(frame, limits)?;
    let (version, value): (u64, T) = ciborium::de::from_reader(frame)
        .map_err(|error| classify_decode_error(error.to_string()))?;
    if version != u64::from(PROTOCOL_VERSION) {
        return Err(CodecError::UnsupportedVersion {
            received: version,
            supported: PROTOCOL_VERSION,
        });
    }
    Ok(Versioned {
        version: PROTOCOL_VERSION,
        value,
    })
}

pub fn canonical_bytes<T: Serialize>(
    value: &T,
    limits: &CodecLimits,
) -> Result<Vec<u8>, CodecError> {
    let bytes = encode_canonical(value, limits)?;
    validate_canonical_item(&bytes, limits)?;
    Ok(bytes)
}

fn encode_canonical<T: Serialize>(value: &T, limits: &CodecLimits) -> Result<Vec<u8>, CodecError> {
    let mut serialized = Vec::with_capacity(512);
    ciborium::ser::into_writer(value, &mut serialized)
        .map_err(|error| CodecError::Message(error.to_string()))?;
    if serialized.len() > limits.max_frame_bytes {
        return Err(CodecError::LimitExceeded {
            limit: "max_frame_bytes",
        });
    }
    // Struct field order is not canonical CBOR key order, so a typical frame
    // fails this check. Reordering map entries in the existing buffer keeps
    // the wire bytes identical without a Value-tree rebuild.
    if validate_canonical_item(&serialized, limits).is_ok() {
        return Ok(serialized);
    }
    let reordered = reorder_map_keys(&mut serialized);
    if let Err(ReorderError::Duplicate) = reordered {
        return Err(CodecError::Malformed {
            code: "duplicateMapKey",
        });
    }
    if reordered.is_ok() && validate_canonical_item(&serialized, limits).is_ok() {
        return Ok(serialized);
    }
    let mut fresh = Vec::with_capacity(serialized.len());
    ciborium::ser::into_writer(value, &mut fresh)
        .map_err(|error| CodecError::Message(error.to_string()))?;
    canonicalize_via_value(&fresh, limits)
}

fn canonicalize_via_value(serialized: &[u8], limits: &CodecLimits) -> Result<Vec<u8>, CodecError> {
    let mut value: ciborium::value::Value = ciborium::de::from_reader(serialized)
        .map_err(|error| CodecError::Message(error.to_string()))?;
    canonicalize_value(&mut value)?;
    let mut canonical = Vec::with_capacity(serialized.len());
    ciborium::ser::into_writer(&value, &mut canonical)
        .map_err(|error| CodecError::Message(error.to_string()))?;
    if canonical.len() > limits.max_frame_bytes {
        return Err(CodecError::LimitExceeded {
            limit: "max_frame_bytes",
        });
    }
    Ok(canonical)
}

fn canonicalize_value(value: &mut ciborium::value::Value) -> Result<(), CodecError> {
    match value {
        ciborium::value::Value::Array(items) => {
            for item in items {
                canonicalize_value(item)?;
            }
        }
        ciborium::value::Value::Map(entries) => {
            let mut canonical = Vec::with_capacity(entries.len());
            for (mut key, mut value) in std::mem::take(entries) {
                canonicalize_value(&mut key)?;
                canonicalize_value(&mut value)?;
                let mut encoded_key = Vec::new();
                ciborium::ser::into_writer(&key, &mut encoded_key)
                    .map_err(|error| CodecError::Message(error.to_string()))?;
                canonical.push((encoded_key, key, value));
            }
            canonical.sort_unstable_by(|left, right| left.0.cmp(&right.0));
            if canonical.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(CodecError::Malformed {
                    code: "duplicateMapKey",
                });
            }
            *entries = canonical
                .into_iter()
                .map(|(_, key, value)| (key, value))
                .collect();
        }
        _ => {}
    }
    Ok(())
}

enum ReorderError {
    Duplicate,
    Fallback,
}

/// Sorts CBOR map entries by encoded key, bottom-up, without changing item
/// widths. ciborium already emits preferred integer and float encodings, so
/// key order is the only non-canonical residue on the encode path.
fn reorder_map_keys(buf: &mut [u8]) -> Result<(), ReorderError> {
    let mut offset = 0;
    let mut scratch = Vec::new();
    rewrite_item(buf, &mut offset, &mut scratch)?;
    if offset == buf.len() {
        Ok(())
    } else {
        Err(ReorderError::Fallback)
    }
}

fn rewrite_item(
    buf: &mut [u8],
    offset: &mut usize,
    scratch: &mut Vec<u8>,
) -> Result<(), ReorderError> {
    let (major, argument) = read_cbor_head(buf, offset)?;
    match major {
        Major::Unsigned | Major::Negative => Ok(()),
        Major::Bytes | Major::Text => {
            let len = usize::try_from(argument).map_err(|_| ReorderError::Fallback)?;
            *offset = offset.checked_add(len).ok_or(ReorderError::Fallback)?;
            if *offset > buf.len() {
                Err(ReorderError::Fallback)
            } else {
                Ok(())
            }
        }
        Major::Tag => rewrite_item(buf, offset, scratch),
        Major::Array => {
            let count = usize::try_from(argument).map_err(|_| ReorderError::Fallback)?;
            for _ in 0..count {
                rewrite_item(buf, offset, scratch)?;
            }
            Ok(())
        }
        Major::Map => rewrite_map(buf, offset, argument, scratch),
        Major::Special => skip_special(buf, offset, argument),
    }
}

fn skip_special(buf: &[u8], offset: &mut usize, additional: u64) -> Result<(), ReorderError> {
    let extra = match additional {
        0..=23 => 0,
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(ReorderError::Fallback),
    };
    *offset = offset.checked_add(extra).ok_or(ReorderError::Fallback)?;
    if *offset > buf.len() {
        Err(ReorderError::Fallback)
    } else {
        Ok(())
    }
}

fn rewrite_map(
    buf: &mut [u8],
    offset: &mut usize,
    count: u64,
    scratch: &mut Vec<u8>,
) -> Result<(), ReorderError> {
    let count = usize::try_from(count).map_err(|_| ReorderError::Fallback)?;
    let body_start = *offset;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let key_start = *offset;
        rewrite_item(buf, offset, scratch)?;
        let key_end = *offset;
        rewrite_item(buf, offset, scratch)?;
        entries.push((key_start, key_end, *offset));
    }
    let body_end = *offset;
    if count < 2 {
        return Ok(());
    }
    let mut order: Vec<usize> = (0..count).collect();
    order.sort_unstable_by(|&left, &right| {
        buf[entries[left].0..entries[left].1].cmp(&buf[entries[right].0..entries[right].1])
    });
    if order.windows(2).any(|pair| {
        buf[entries[pair[0]].0..entries[pair[0]].1] == buf[entries[pair[1]].0..entries[pair[1]].1]
    }) {
        return Err(ReorderError::Duplicate);
    }
    if order.iter().enumerate().all(|(index, item)| index == *item) {
        return Ok(());
    }
    scratch.clear();
    for index in order {
        let (key_start, _, value_end) = entries[index];
        scratch.extend_from_slice(&buf[key_start..value_end]);
    }
    if scratch.len() != body_end - body_start {
        return Err(ReorderError::Fallback);
    }
    buf[body_start..body_end].copy_from_slice(scratch);
    Ok(())
}

fn read_cbor_head(input: &[u8], offset: &mut usize) -> Result<(Major, u64), ReorderError> {
    if *offset >= input.len() {
        return Err(ReorderError::Fallback);
    }
    let initial = input[*offset];
    *offset += 1;
    let major = match initial >> 5 {
        0 => Major::Unsigned,
        1 => Major::Negative,
        2 => Major::Bytes,
        3 => Major::Text,
        4 => Major::Array,
        5 => Major::Map,
        6 => Major::Tag,
        _ => Major::Special,
    };
    let additional = initial & 0x1f;
    if major == Major::Special {
        return Ok((major, u64::from(additional)));
    }
    if additional >= 28 {
        return Err(ReorderError::Fallback);
    }
    if additional < 24 {
        return Ok((major, u64::from(additional)));
    }
    let len = 1usize << (additional - 24);
    if input.len() - *offset < len {
        return Err(ReorderError::Fallback);
    }
    let mut value = 0u64;
    for _ in 0..len {
        value = (value << 8) | u64::from(input[*offset]);
        *offset += 1;
    }
    Ok((major, value))
}

fn classify_decode_error(message: String) -> CodecError {
    for prefix in ["unknown variant `", "unknown variant "] {
        if let Some(rest) = message.split_once(prefix).map(|(_, rest)| rest) {
            let end = rest.find(['`', ',', ' ']).unwrap_or(rest.len());
            return CodecError::UnknownKind {
                kind: rest[..end].to_owned(),
            };
        }
    }
    CodecError::Message(message)
}

fn validate_frame(frame: &[u8], limits: &CodecLimits) -> Result<(), CodecError> {
    if frame.len() > limits.max_frame_bytes {
        return Err(CodecError::LimitExceeded {
            limit: "max_frame_bytes",
        });
    }
    let mut validator = Validator::new(frame, *limits);
    let (major, count) = validator.read_head()?;
    if major != Major::Array || count != 2 {
        return Err(CodecError::Malformed {
            code: "expectedFrameArray",
        });
    }
    let (major, version) = validator.read_head()?;
    if major != Major::Unsigned {
        return Err(CodecError::Malformed {
            code: "expectedVersion",
        });
    }
    if version != u64::from(PROTOCOL_VERSION) {
        return Err(CodecError::UnsupportedVersion {
            received: version,
            supported: PROTOCOL_VERSION,
        });
    }
    validator.item(1)?;
    validator.finish()
}

fn validate_canonical_item(bytes: &[u8], limits: &CodecLimits) -> Result<(), CodecError> {
    if bytes.len() > limits.max_frame_bytes {
        return Err(CodecError::LimitExceeded {
            limit: "max_frame_bytes",
        });
    }
    let mut validator = Validator::new(bytes, *limits);
    validator.item(0)?;
    validator.finish()
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Major {
    Unsigned,
    Negative,
    Bytes,
    Text,
    Array,
    Map,
    Tag,
    Special,
}

struct Validator<'a> {
    input: &'a [u8],
    offset: usize,
    limits: CodecLimits,
}

impl<'a> Validator<'a> {
    fn new(input: &'a [u8], limits: CodecLimits) -> Self {
        Self {
            input,
            offset: 0,
            limits,
        }
    }

    fn finish(&self) -> Result<(), CodecError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(CodecError::Malformed {
                code: "trailingBytes",
            })
        }
    }

    fn take(&mut self, len: usize, code: &'static str) -> Result<&'a [u8], CodecError> {
        if self.input.len().saturating_sub(self.offset) < len {
            return Err(CodecError::Malformed { code });
        }
        let bytes = &self.input[self.offset..self.offset + len];
        self.offset += len;
        Ok(bytes)
    }

    fn read_head(&mut self) -> Result<(Major, u64), CodecError> {
        let initial = self.take(1, "truncatedHead")?[0];
        let major = match initial >> 5 {
            0 => Major::Unsigned,
            1 => Major::Negative,
            2 => Major::Bytes,
            3 => Major::Text,
            4 => Major::Array,
            5 => Major::Map,
            6 => Major::Tag,
            _ => Major::Special,
        };
        let additional = initial & 0x1f;
        let argument = if major == Major::Special {
            match additional {
                0..=23 => u64::from(additional),
                25..=27 => u64::from(additional),
                24 => {
                    self.take(1, "truncatedSimple")?;
                    return Err(CodecError::Malformed {
                        code: "unsupportedSimple",
                    });
                }
                28..=30 => {
                    return Err(CodecError::Malformed {
                        code: "reservedHead",
                    });
                }
                _ => {
                    return Err(CodecError::Malformed {
                        code: "indefiniteLength",
                    });
                }
            }
        } else {
            match additional {
                0..=23 => u64::from(additional),
                24..=27 => {
                    let len = 1usize << (additional - 24);
                    let bytes = self.take(len, "truncatedHead")?;
                    let mut value = 0u64;
                    for byte in bytes {
                        value = (value << 8) | u64::from(*byte);
                    }
                    let minimum = match additional {
                        24 => 24,
                        25 => 0x100,
                        26 => 0x1_0000,
                        _ => 0x1_0000_0000,
                    };
                    if value < minimum {
                        return Err(CodecError::Malformed {
                            code: "overlongHead",
                        });
                    }
                    value
                }
                28..=30 => {
                    return Err(CodecError::Malformed {
                        code: "reservedHead",
                    });
                }
                _ => {
                    return Err(CodecError::Malformed {
                        code: "indefiniteLength",
                    });
                }
            }
        };
        Ok((major, argument))
    }

    fn item(&mut self, depth: u8) -> Result<(), CodecError> {
        if depth > self.limits.max_depth {
            return Err(CodecError::LimitExceeded { limit: "max_depth" });
        }
        let (major, argument) = self.read_head()?;
        match major {
            Major::Unsigned | Major::Negative => Ok(()),
            Major::Tag => Err(CodecError::Malformed {
                code: "unexpectedTag",
            }),
            Major::Bytes => {
                if argument > self.limits.max_frame_bytes as u64 {
                    return Err(CodecError::LimitExceeded {
                        limit: "max_frame_bytes",
                    });
                }
                self.take(argument as usize, "truncatedBytes").map(|_| ())
            }
            Major::Text => {
                if argument > self.limits.max_text_bytes as u64 {
                    return Err(CodecError::LimitExceeded {
                        limit: "max_text_bytes",
                    });
                }
                let bytes = self.take(argument as usize, "truncatedText")?;
                std::str::from_utf8(bytes)
                    .map(|_| ())
                    .map_err(|_| CodecError::Malformed {
                        code: "invalidUtf8",
                    })
            }
            Major::Array => {
                self.check_items(argument)?;
                for _ in 0..argument {
                    self.item(depth + 1)?;
                }
                Ok(())
            }
            Major::Map => {
                self.check_items(argument)?;
                let mut previous: Option<&'a [u8]> = None;
                for _ in 0..argument {
                    let key_start = self.offset;
                    self.item(depth + 1)?;
                    let key = &self.input[key_start..self.offset];
                    if let Some(previous) = previous {
                        if key <= previous {
                            return Err(CodecError::Malformed {
                                code: if key == previous {
                                    "duplicateMapKey"
                                } else {
                                    "unsortedMapKeys"
                                },
                            });
                        }
                    }
                    previous = Some(key);
                    self.item(depth + 1)?;
                }
                Ok(())
            }
            Major::Special => self.special(argument),
        }
    }

    fn check_items(&self, count: u64) -> Result<(), CodecError> {
        if count > self.limits.max_container_items as u64 {
            Err(CodecError::LimitExceeded {
                limit: "max_container_items",
            })
        } else {
            Ok(())
        }
    }

    fn special(&mut self, additional: u64) -> Result<(), CodecError> {
        match additional {
            20..=22 => Ok(()),
            25 => {
                let bytes = self.take(2, "truncatedFloat")?;
                let bits = u16::from_be_bytes([bytes[0], bytes[1]]);
                if bits & 0x7fff > 0x7c00 && bits != 0x7e00 {
                    return Err(CodecError::Malformed {
                        code: "nonCanonicalNan",
                    });
                }
                Ok(())
            }
            26 => {
                let bytes = self.take(4, "truncatedFloat")?;
                let value =
                    f32::from_bits(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                if f16_exact(value) {
                    return Err(CodecError::Malformed {
                        code: "nonMinimalFloat",
                    });
                }
                Ok(())
            }
            27 => {
                let bytes = self.take(8, "truncatedFloat")?;
                let value = f64::from_bits(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]));
                if value.is_nan() || (value as f32) as f64 == value {
                    return Err(CodecError::Malformed {
                        code: "nonMinimalFloat",
                    });
                }
                Ok(())
            }
            _ => Err(CodecError::Malformed {
                code: "unsupportedSimple",
            }),
        }
    }
}

fn f16_exact(value: f32) -> bool {
    if value.is_nan() || value.is_infinite() || value == 0.0 {
        return true;
    }
    let bits = value.to_bits();
    let exponent = ((bits >> 23) & 0xff) as i32 - 127;
    let fraction = bits & 0x007f_ffff;
    if (-14..=15).contains(&exponent) {
        return fraction & 0x1fff == 0;
    }
    if exponent < -14 {
        let shift = (-14 - exponent) as u32;
        if shift >= 24 {
            return false;
        }
        let mantissa = fraction | 0x0080_0000;
        return mantissa >> (13 + shift) != 0 && mantissa & ((1 << (13 + shift)) - 1) == 0;
    }
    false
}

/// Converts a serializable protocol value to bounded redacted JSON. Binary
/// arrays are replaced by length markers and long text by truncated markers;
/// callers never need to serialize protocol values directly for debug output.
pub fn redacted_json<T: Serialize>(
    value: &T,
    limits: &CodecLimits,
) -> Result<serde_json::Value, CodecError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| CodecError::Message(error.to_string()))?;
    redact_value(&mut value, 0, limits)?;
    Ok(value)
}

fn redact_value(
    value: &mut serde_json::Value,
    depth: u8,
    limits: &CodecLimits,
) -> Result<(), CodecError> {
    if depth > limits.max_depth {
        return Err(CodecError::LimitExceeded { limit: "max_depth" });
    }
    match value {
        serde_json::Value::String(text) if text.len() > MAX_DEBUG_TEXT_BYTES => {
            let mut end = 128.min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            let marker = serde_json::json!({
                "redacted": "truncatedText",
                "prefix": &text[..end],
                "len": text.len(),
            });
            *value = marker;
        }
        serde_json::Value::Array(items) => {
            if items.len() > limits.max_container_items {
                return Err(CodecError::LimitExceeded {
                    limit: "max_container_items",
                });
            }
            if !items.is_empty()
                && items.iter().all(|item| {
                    item.as_u64()
                        .map(|byte| byte <= u64::from(u8::MAX))
                        .unwrap_or(false)
                })
            {
                *value = serde_json::json!({ "redacted": "binary", "len": items.len() });
            } else {
                for item in items {
                    redact_value(item, depth + 1, limits)?;
                }
            }
        }
        serde_json::Value::Object(object) => {
            if object.len() > limits.max_container_items {
                return Err(CodecError::LimitExceeded {
                    limit: "max_container_items",
                });
            }
            for (key, child) in object {
                if key == "ticket" {
                    *child = serde_json::json!({ "redacted": "contentTicket" });
                } else {
                    redact_value(child, depth + 1, limits)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use odin_domain::huginn::{
        HuginnMessage, HuginnProtocolError, LiveProtocolError, LiveServerMessage,
    };
    use serde::{Deserialize, Serialize};

    use crate::protocol::{ClientFrame, ServerFrame};

    use super::{decode_frame, encode_frame, CodecError, CodecLimits, PROTOCOL_VERSION};

    #[test]
    fn envelope_round_trips() {
        let value = vec!["alpha", "beta"];
        let frame = encode_frame(&value, &CodecLimits::default()).expect("encode");
        let decoded = decode_frame::<Vec<String>>(&frame, &CodecLimits::default()).expect("decode");
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.value, value);
    }
    #[test]
    fn nested_protocol_errors_round_trip_without_discriminant_collisions() {
        let frames = [
            ServerFrame::General(HuginnMessage::ProtocolError(
                HuginnProtocolError::Unavailable {
                    code: "generalUnavailable".to_owned(),
                },
            )),
            ServerFrame::Live(LiveServerMessage::ProtocolError(
                LiveProtocolError::Unavailable {
                    code: "liveUnavailable".to_owned(),
                },
            )),
        ];
        for frame in frames {
            let encoded = encode_frame(&frame, &CodecLimits::default()).expect("encode");
            let decoded =
                decode_frame::<ServerFrame>(&encoded, &CodecLimits::default()).expect("decode");
            assert_eq!(decoded.value, frame);
        }
    }

    #[test]
    fn encoder_canonicalizes_struct_map_keys() {
        #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
        struct OutOfOrder {
            z: u8,
            a: u8,
        }

        let value = OutOfOrder { z: 1, a: 2 };
        let frame = encode_frame(&value, &CodecLimits::default()).expect("encode");
        assert_eq!(
            frame,
            [0x82, 0x01, 0xa2, 0x61, b'a', 0x02, 0x61, b'z', 0x01]
        );
        let decoded = decode_frame::<OutOfOrder>(&frame, &CodecLimits::default()).expect("decode");
        assert_eq!(decoded.value, value);
    }

    #[test]
    fn rejects_non_canonical_and_wrong_version() {
        let limits = CodecLimits::default();
        assert!(matches!(
            decode_frame::<u8>(&[0x82, 0x18, 0x01, 0x00], &limits),
            Err(CodecError::Malformed {
                code: "overlongHead"
            })
        ));
        assert!(matches!(
            decode_frame::<u8>(&[0x82, 0x02, 0x00], &limits),
            Err(CodecError::UnsupportedVersion { received: 2, .. })
        ));
    }

    #[test]
    fn client_subscribe_frame_round_trips_through_server_decode() {
        use std::num::{NonZeroU32, NonZeroU64};

        use odin_domain::huginn::{
            HuginnRequest, LiveStreamKind, Sequence, StreamBackpressureLimits, StreamCredit,
            StreamCursor, StreamId, StreamSubscription, SubscriptionSet,
        };

        let frame = ClientFrame::General(HuginnRequest::Subscribe(SubscriptionSet {
            subscriptions: vec![StreamSubscription {
                kind: LiveStreamKind::AgentEvents,
                cursor: StreamCursor::Durable {
                    stream_id: StreamId::parse("00000000-0000-4000-8000-000000000004")
                        .expect("stream id"),
                    after: Some(Sequence::new(0)),
                },
                credit: StreamCredit {
                    items: NonZeroU32::new(64).expect("credit items"),
                    bytes: NonZeroU64::new(1 << 20).expect("credit bytes"),
                },
                limits: StreamBackpressureLimits {
                    max_buffered_items: NonZeroU32::new(1024).expect("buffered items"),
                    max_buffered_bytes: NonZeroU64::new(1 << 24).expect("buffered bytes"),
                    max_item_bytes: NonZeroU64::new(1 << 20).expect("item bytes"),
                    max_items_per_second: NonZeroU32::new(256).expect("items per second"),
                    max_in_flight_bytes: NonZeroU64::new(1 << 22).expect("in-flight bytes"),
                },
            }],
        }));
        let encoded = encode_frame(&frame, &CodecLimits::default()).expect("encode");
        let decoded =
            decode_frame::<ClientFrame>(&encoded, &CodecLimits::default()).expect("decode");
        assert_eq!(decoded.value, frame);
    }

    #[test]
    fn encoder_canonicalizes_nested_maps_without_changing_widths() {
        #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
        struct Inner {
            z: u8,
            a: u8,
        }
        #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
        struct Outer {
            z: Inner,
            a: u8,
        }

        let value = Outer {
            z: Inner { z: 1, a: 2 },
            a: 3,
        };
        let frame = encode_frame(&value, &CodecLimits::default()).expect("encode");
        assert_eq!(
            frame,
            [
                0x82, 0x01, 0xa2, 0x61, b'a', 0x03, 0x61, b'z', 0xa2, 0x61, b'a', 0x02, 0x61, b'z',
                0x01
            ]
        );
        let decoded = decode_frame::<Outer>(&frame, &CodecLimits::default()).expect("decode");
        assert_eq!(decoded.value, value);
    }

    #[test]
    fn encoder_rejects_duplicate_map_keys() {
        struct DuplicateKeys;

        impl Serialize for DuplicateKeys {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeMap as _;
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("a", &1u8)?;
                map.serialize_entry("a", &2u8)?;
                map.end()
            }
        }

        assert!(matches!(
            encode_frame(&DuplicateKeys, &CodecLimits::default()),
            Err(CodecError::Malformed {
                code: "duplicateMapKey"
            })
        ));
    }
}
