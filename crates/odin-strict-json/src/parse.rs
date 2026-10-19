//! Validate wire syntax and duplicate keys before serde performs typed deserialization.

use std::collections::HashMap;

use serde::de::DeserializeOwned;

use crate::error::{DecodeError, DecodeOptions};
use crate::value::{ObjectEntry, Value};

/// Unknown fields are rejected only when the target uses `serde(deny_unknown_fields)`.
pub fn decode<T>(bytes: &[u8], byte_ceiling: usize) -> Result<T, DecodeError>
where
    T: DeserializeOwned,
{
    decode_with_options(
        bytes,
        DecodeOptions {
            byte_ceiling,
            max_depth: 128,
        },
    )
}

pub fn decode_with_options<T>(bytes: &[u8], opts: DecodeOptions) -> Result<T, DecodeError>
where
    T: DeserializeOwned,
{
    let value = parse(bytes, opts)?;
    // Canonical encoding gives serde a validated, duplicate-free document.
    let canonical =
        crate::canonical::canonicalize_value(&value).map_err(decode_error_from_canonical)?;
    serde_json::from_slice(&canonical).map_err(translate_serde_error)
}

fn translate_serde_error(err: serde_json::Error) -> DecodeError {
    use odin_types::gate::ReasonCategory;
    let msg = err.to_string();
    if msg.contains("unknown field") {
        return DecodeError::TypedMismatch {
            category: ReasonCategory::UnknownField,
            code: "json.unknown_field",
            message: msg,
        };
    }
    if msg.contains("invalid type") {
        return DecodeError::TypedMismatch {
            category: ReasonCategory::UnparseableShape,
            code: "json.invalid_type",
            message: msg,
        };
    }
    if looks_like_id_error(&msg) {
        return DecodeError::TypedMismatch {
            category: ReasonCategory::MalformedId,
            code: "id.malformed",
            message: msg,
        };
    }
    DecodeError::TypedMismatch {
        category: ReasonCategory::UnparseableShape,
        code: "json.deserialize",
        message: msg,
    }
}

fn looks_like_id_error(msg: &str) -> bool {
    // ID errors start with the kind name, allowing typed error classification.
    const KINDS: &[&str] = &[
        "ToolId",
        "CapsuleId",
        "OperationId",
        "CorrelationId",
        "PredecessorHash",
    ];
    KINDS.iter().any(|k| msg.contains(k))
}

fn decode_error_from_canonical(e: crate::canonical::CanonicalError) -> DecodeError {
    match e {
        crate::canonical::CanonicalError::NonFiniteNumber { offset } => {
            DecodeError::NonFiniteNumber { offset }
        }
        other => unreachable!("parsed values always encode canonically: {other}"),
    }
}

pub fn parse(bytes: &[u8], opts: DecodeOptions) -> Result<Value, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::Empty);
    }
    if bytes.len() > opts.byte_ceiling {
        return Err(DecodeError::ByteCeiling {
            size: bytes.len(),
            ceiling: opts.byte_ceiling,
        });
    }
    let mut parser = Parser::new(bytes, opts);
    parser.skip_ws();
    let value = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos < parser.input.len() {
        return Err(DecodeError::TrailingData { offset: parser.pos });
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    opts: DecodeOptions,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8], opts: DecodeOptions) -> Self {
        Self {
            input,
            pos: 0,
            opts,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.input.len() {
            let b = self.input[self.pos];
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn expect(&mut self, b: u8, expected: &'static str) -> Result<(), DecodeError> {
        match self.bump() {
            Some(actual) if actual == b => Ok(()),
            Some(other) => Err(DecodeError::UnexpectedToken {
                offset: self.pos - 1,
                found: format!("0x{other:02x}"),
                expected,
            }),
            None => Err(DecodeError::UnexpectedEof),
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if self.opts.max_depth != 0 && depth >= self.opts.max_depth {
            return Err(DecodeError::MaxDepthExceeded {
                depth,
                offset: self.pos,
            });
        }
        let b = self.peek().ok_or(DecodeError::UnexpectedEof)?;
        match b {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'"' => self.parse_string().map(Value::String),
            b't' | b'f' => self.parse_bool(),
            b'n' => self.parse_null(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(DecodeError::UnexpectedToken {
                offset: self.pos,
                found: format!("0x{other:02x}"),
                expected: "JSON value",
            }),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<Value, DecodeError> {
        self.expect(b'{', "`{`")?;
        let mut entries: Vec<ObjectEntry> = Vec::new();
        // Keep the first offset so duplicate-key errors identify both occurrences.
        let mut seen: HashMap<String, usize> = HashMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(entries));
        }
        loop {
            self.skip_ws();
            let key_offset = self.pos;
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':', "`:`")?;
            self.skip_ws();
            let value = self.parse_value(depth + 1)?;
            if let Some(&first_offset) = seen.get(&key) {
                return Err(DecodeError::DuplicateKey {
                    key,
                    first_offset,
                    second_offset: key_offset,
                });
            }
            seen.insert(key.clone(), key_offset);
            entries.push(ObjectEntry { key, value });
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(entries));
                }
                Some(other) => {
                    return Err(DecodeError::UnexpectedToken {
                        offset: self.pos,
                        found: format!("0x{other:02x}"),
                        expected: "`,` or `}`",
                    });
                }
                None => return Err(DecodeError::UnexpectedEof),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Value, DecodeError> {
        self.expect(b'[', "`[`")?;
        let mut items: Vec<Value> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_ws();
            let v = self.parse_value(depth + 1)?;
            items.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                Some(other) => {
                    return Err(DecodeError::UnexpectedToken {
                        offset: self.pos,
                        found: format!("0x{other:02x}"),
                        expected: "`,` or `]`",
                    });
                }
                None => return Err(DecodeError::UnexpectedEof),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, DecodeError> {
        self.expect(b'"', "`\"`")?;
        let mut out = String::new();
        loop {
            let b = self.bump().ok_or(DecodeError::UnexpectedEof)?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.bump().ok_or(DecodeError::UnexpectedEof)?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\x08'),
                        b'f' => out.push('\x0c'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let escape_offset = self.pos;
                            let unit = self.parse_hex4()?;
                            let ch = self.codepoint_from_unit(escape_offset, unit)?;
                            out.push(ch);
                        }
                        other => {
                            return Err(DecodeError::InvalidEscape {
                                offset: self.pos - 1,
                                byte: other,
                            });
                        }
                    }
                }
                _ => {
                    if b < 0x20 {
                        return Err(DecodeError::InvalidEscape {
                            offset: self.pos - 1,
                            byte: b,
                        });
                    }
                    // Decode the full UTF-8 sequence before appending a character.
                    let start = self.pos - 1;
                    let char_len = utf8_char_len(b);
                    if char_len == 0 || start + char_len > self.input.len() {
                        return Err(DecodeError::InvalidUnicode { offset: start });
                    }
                    let slice = &self.input[start..start + char_len];
                    let ch = std::str::from_utf8(slice)
                        .map_err(|_| DecodeError::InvalidUnicode { offset: start })?
                        .chars()
                        .next()
                        .expect("non-empty");
                    out.push(ch);
                    self.pos = start + char_len;
                }
            }
        }
    }

    /// Check digits explicitly because from_str_radix accepts a plus sign forbidden by JSON.
    fn parse_hex4(&mut self) -> Result<u16, DecodeError> {
        let start = self.pos;
        if start + 4 > self.input.len() {
            return Err(DecodeError::InvalidUnicode { offset: start });
        }
        let raw = &self.input[start..start + 4];
        if !raw.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(DecodeError::InvalidUnicode { offset: start });
        }
        let digits =
            std::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUnicode { offset: start })?;
        let unit = u16::from_str_radix(digits, 16)
            .map_err(|_| DecodeError::InvalidUnicode { offset: start })?;
        self.pos += 4;
        Ok(unit)
    }

    fn codepoint_from_unit(
        &mut self,
        escape_offset: usize,
        unit: u16,
    ) -> Result<char, DecodeError> {
        match unit {
            0xDC00..=0xDFFF => Err(DecodeError::InvalidUnicode {
                offset: escape_offset,
            }),
            0xD800..=0xDBFF => {
                if self.peek() != Some(b'\\') || self.input.get(self.pos + 1) != Some(&b'u') {
                    return Err(DecodeError::InvalidUnicode { offset: self.pos });
                }
                self.pos += 2;
                let low_offset = self.pos;
                let low = self.parse_hex4()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(DecodeError::InvalidUnicode { offset: low_offset });
                }
                let combined =
                    0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                Ok(char::from_u32(combined).expect("surrogate pair yields a scalar value"))
            }
            _ => Ok(char::from_u32(u32::from(unit))
                .expect("non-surrogate BMP escape yields a scalar value")),
        }
    }

    fn parse_bool(&mut self) -> Result<Value, DecodeError> {
        if self.input[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Value::Bool(true))
        } else if self.input[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Value::Bool(false))
        } else {
            Err(DecodeError::InvalidLiteral {
                offset: self.pos,
                source: "expected `true` or `false`".to_string(),
            })
        }
    }

    fn parse_null(&mut self) -> Result<Value, DecodeError> {
        if self.input[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(Value::Null)
        } else {
            Err(DecodeError::InvalidLiteral {
                offset: self.pos,
                source: "expected `null`".to_string(),
            })
        }
    }

    fn parse_number(&mut self) -> Result<Value, DecodeError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // JSON forbids leading zeros except for the integer zero itself.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if let Some(b'0'..=b'9') = self.peek() {
                    return Err(DecodeError::InvalidNumber {
                        offset: self.pos,
                        source: "leading zeros are forbidden".to_string(),
                    });
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while let Some(b'0'..=b'9') = self.peek() {
                    self.pos += 1;
                }
            }
            _ => {
                return Err(DecodeError::InvalidNumber {
                    offset: self.pos,
                    source: "expected leading digit".to_string(),
                });
            }
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            let frac_start = self.pos;
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return Err(DecodeError::InvalidNumber {
                    offset: self.pos,
                    source: "expected digits after `.`".to_string(),
                });
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return Err(DecodeError::InvalidNumber {
                    offset: self.pos,
                    source: "expected digits in exponent".to_string(),
                });
            }
        }
        let raw = std::str::from_utf8(&self.input[start..self.pos]).map_err(|_| {
            DecodeError::InvalidNumber {
                offset: start,
                source: "non-UTF-8 number".to_string(),
            }
        })?;
        if is_float {
            // Reject NaN/Inf forms explicitly. JSON does not permit them.
            let f: f64 = raw.parse().map_err(|e| DecodeError::InvalidNumber {
                offset: start,
                source: format!("{e}"),
            })?;
            if !f.is_finite() {
                return Err(DecodeError::NonFiniteNumber { offset: start });
            }
            Ok(Value::Float(f))
        } else if raw.starts_with('-') {
            let n: i64 = raw.parse().map_err(|_| DecodeError::InvalidNumber {
                offset: start,
                source: "integer is below the i64 minimum".to_string(),
            })?;
            Ok(Value::Int(n))
        } else {
            let u: u64 = raw.parse().map_err(|_| DecodeError::InvalidNumber {
                offset: start,
                source: "integer is above the u64 maximum".to_string(),
            })?;
            if u <= i64::MAX as u64 {
                Ok(Value::Int(u as i64))
            } else {
                Ok(Value::UInt(u))
            }
        }
    }
}

fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b < 0xc0 {
        // Continuation byte at the start of a char is malformed UTF-8.
        0
    } else if b < 0xe0 {
        2
    } else if b < 0xf0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonicalize_string;

    fn strict(input: &[u8]) -> Value {
        parse(input, DecodeOptions::default()).expect("valid wire input parses")
    }

    fn string_of(input: &[u8]) -> String {
        match strict(input) {
            Value::String(s) => s,
            other => panic!("expected a string value, got {}", other.kind()),
        }
    }

    fn rejects_lone_surrogate(input: &[u8]) {
        assert!(
            matches!(
                parse(input, DecodeOptions::default()),
                Err(DecodeError::InvalidUnicode { .. })
            ),
            "expected InvalidUnicode for {:?}",
            String::from_utf8_lossy(input)
        );
    }

    /// Valid UTF-16 surrogate pairs join into scalar values in every
    /// string position; lone, reversed, mismatched, and truncated
    /// surrogates are rejected; canonical output keeps the lowercase
    /// `\uXXXX` surrogate form for the supported domain.
    #[test]
    fn unicode_surrogate_pairs() {
        assert_eq!(string_of(br#""\ud83d\ude00""#), "😀");
        assert_eq!(string_of(br#""\ud834\udd1e""#), "𝄞");
        assert_eq!(
            string_of(br#""\uD83D\uDE00""#),
            "😀",
            "hex digits are case-insensitive"
        );
        assert_eq!(string_of(r#""a😀béc""#.as_bytes()), "a😀béc");
        assert_eq!(
            string_of(br#""a\ud83d\ude00b\u00e9c""#),
            "a😀béc",
            "pairs mix freely with plain UTF-8 and BMP escapes"
        );
        assert_eq!(
            string_of(br#""\ud800\udc00\ud801\udc37""#),
            "\u{10000}\u{10437}",
            "consecutive pairs each join"
        );

        match strict(br#"{"\ud83d\ude00":1}"#) {
            Value::Object(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].key, "😀");
            }
            other => panic!("expected an object, got {}", other.kind()),
        }

        let parsed = strict(r#""😀""#.as_bytes());
        assert_eq!(
            canonicalize_string(&parsed).expect("canonicalizes"),
            r#""\ud83d\ude00""#,
            "canonical output escapes astral planes as lowercase surrogate pairs"
        );

        rejects_lone_surrogate(br#""\ud800""#);
        rejects_lone_surrogate(br#""\udbff""#);
        rejects_lone_surrogate(br#""\udc00""#);
        rejects_lone_surrogate(br#""\udfff""#);
        rejects_lone_surrogate(br#""\udc00\ud800""#);
        rejects_lone_surrogate(br#""\ud800\ud800""#);
        rejects_lone_surrogate(br#""\ud800\u0041""#);
        rejects_lone_surrogate(br#""\ud800\n""#);
        rejects_lone_surrogate(br#""\ud800x""#);
        rejects_lone_surrogate(br#""\ud83""#);
        rejects_lone_surrogate(br#"{"\ud800":1}"#);
        rejects_lone_surrogate(br#""\u+123""#);
        rejects_lone_surrogate(br#""\u-123""#);

        let round_trip = strict(r#"{"😀":["𝄞",null]}"#.as_bytes());
        let bytes = crate::canonical::canonicalize_value(&round_trip).expect("canonicalizes");
        assert_eq!(
            parse(&bytes, DecodeOptions::default()).expect("reparses"),
            round_trip
        );
    }
}
