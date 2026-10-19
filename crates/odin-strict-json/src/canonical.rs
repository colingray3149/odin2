//! Match Python's sorted compact JSON with ensure_ascii=True so equivalent values hash identically.

use std::fmt;
use std::io::Write;

use serde::ser;
use serde::Serialize;

use odin_types::HashHex;

use crate::value::{ObjectEntry, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// JSON has no non-finite numbers; the offset identifies the number in the output stream.
    NonFiniteNumber {
        offset: usize,
    },
    /// Serialization cannot produce JSON, for example when a map key has an unsupported type.
    Serialize {
        message: String,
    },
    Io {
        message: String,
    },
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalError::NonFiniteNumber { offset } => {
                write!(f, "non-finite number at offset {offset}")
            }
            CanonicalError::Serialize { message } => {
                write!(f, "serialization rejected: {message}")
            }
            CanonicalError::Io { message } => write!(f, "writer failed: {message}"),
        }
    }
}

impl std::error::Error for CanonicalError {}

impl ser::Error for CanonicalError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        CanonicalError::Serialize {
            message: message.to_string(),
        }
    }
}

fn io_error(error: std::io::Error) -> CanonicalError {
    CanonicalError::Io {
        message: error.to_string(),
    }
}

fn value_from_u64(n: u64) -> Value {
    if n <= i64::MAX as u64 {
        Value::Int(n as i64)
    } else {
        Value::UInt(n)
    }
}

fn value_from_i128(n: i128) -> Result<Value, CanonicalError> {
    if let Ok(v) = i64::try_from(n) {
        Ok(Value::Int(v))
    } else if let Ok(v) = u64::try_from(n) {
        Ok(Value::UInt(v))
    } else {
        Err(CanonicalError::Serialize {
            message: format!("integer {n} is outside the i64/u64 range"),
        })
    }
}

fn value_from_u128(n: u128) -> Result<Value, CanonicalError> {
    match u64::try_from(n) {
        Ok(v) => Ok(value_from_u64(v)),
        Err(_) => Err(CanonicalError::Serialize {
            message: format!("integer {n} is above the u64 maximum"),
        }),
    }
}

fn finite_f64(x: f64) -> Result<Value, CanonicalError> {
    if !x.is_finite() {
        return Err(CanonicalError::NonFiniteNumber { offset: 0 });
    }
    Ok(Value::Float(x))
}

/// Count emitted bytes so non-finite-number errors can identify their output offset.
struct CountingWriter<W> {
    inner: W,
    written: usize,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.written += written;
        Ok(written)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(buf)?;
        self.written += buf.len();
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Copy, Clone)]
struct ValueSerializer;

impl ser::Serializer for ValueSerializer {
    type Ok = Value;
    type Error = CanonicalError;
    type SerializeSeq = SeqBuilder;
    type SerializeTuple = SeqBuilder;
    type SerializeTupleStruct = SeqBuilder;
    type SerializeTupleVariant = TupleVariantBuilder;
    type SerializeMap = MapBuilder;
    type SerializeStruct = MapBuilder;
    type SerializeStructVariant = MapBuilder;

    fn serialize_bool(self, v: bool) -> Result<Value, CanonicalError> {
        Ok(Value::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Value, CanonicalError> {
        Ok(Value::Int(i64::from(v)))
    }

    fn serialize_i16(self, v: i16) -> Result<Value, CanonicalError> {
        Ok(Value::Int(i64::from(v)))
    }

    fn serialize_i32(self, v: i32) -> Result<Value, CanonicalError> {
        Ok(Value::Int(i64::from(v)))
    }

    fn serialize_i64(self, v: i64) -> Result<Value, CanonicalError> {
        Ok(Value::Int(v))
    }

    fn serialize_i128(self, v: i128) -> Result<Value, CanonicalError> {
        value_from_i128(v)
    }

    fn serialize_u8(self, v: u8) -> Result<Value, CanonicalError> {
        Ok(value_from_u64(u64::from(v)))
    }

    fn serialize_u16(self, v: u16) -> Result<Value, CanonicalError> {
        Ok(value_from_u64(u64::from(v)))
    }

    fn serialize_u32(self, v: u32) -> Result<Value, CanonicalError> {
        Ok(value_from_u64(u64::from(v)))
    }

    fn serialize_u64(self, v: u64) -> Result<Value, CanonicalError> {
        Ok(value_from_u64(v))
    }

    fn serialize_u128(self, v: u128) -> Result<Value, CanonicalError> {
        value_from_u128(v)
    }

    fn serialize_f32(self, v: f32) -> Result<Value, CanonicalError> {
        finite_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<Value, CanonicalError> {
        finite_f64(v)
    }

    fn serialize_char(self, v: char) -> Result<Value, CanonicalError> {
        Ok(Value::String(v.to_string()))
    }

    fn serialize_str(self, v: &str) -> Result<Value, CanonicalError> {
        Ok(Value::String(v.to_string()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Value, CanonicalError> {
        Ok(Value::Array(
            v.iter().map(|byte| Value::Int(i64::from(*byte))).collect(),
        ))
    }

    fn serialize_none(self) -> Result<Value, CanonicalError> {
        Ok(Value::Null)
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value, CanonicalError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Value, CanonicalError> {
        Ok(Value::Null)
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value, CanonicalError> {
        Ok(Value::Null)
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Value, CanonicalError> {
        Ok(Value::String(variant.to_string()))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value, CanonicalError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Value, CanonicalError> {
        Ok(Value::Object(vec![ObjectEntry {
            key: variant.to_string(),
            value: value.serialize(self)?,
        }]))
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<SeqBuilder, CanonicalError> {
        Ok(SeqBuilder::new(len))
    }

    fn serialize_tuple(self, len: usize) -> Result<SeqBuilder, CanonicalError> {
        Ok(SeqBuilder::new(Some(len)))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<SeqBuilder, CanonicalError> {
        Ok(SeqBuilder::new(Some(len)))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<TupleVariantBuilder, CanonicalError> {
        Ok(TupleVariantBuilder {
            variant,
            items: Vec::with_capacity(len),
        })
    }

    fn serialize_map(self, len: Option<usize>) -> Result<MapBuilder, CanonicalError> {
        Ok(MapBuilder::new(len, None))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<MapBuilder, CanonicalError> {
        Ok(MapBuilder::new(Some(len), None))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<MapBuilder, CanonicalError> {
        Ok(MapBuilder::new(Some(len), Some(variant)))
    }
}

struct SeqBuilder {
    items: Vec<Value>,
}

impl SeqBuilder {
    fn new(len: Option<usize>) -> Self {
        Self {
            items: Vec::with_capacity(len.unwrap_or(0)),
        }
    }

    fn push<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CanonicalError> {
        self.items.push(value.serialize(ValueSerializer)?);
        Ok(())
    }
}

impl ser::SerializeSeq for SeqBuilder {
    type Ok = Value;
    type Error = CanonicalError;

    fn serialize_element<T: ?Sized + Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.push(value)
    }

    fn end(self) -> Result<Value, CanonicalError> {
        Ok(Value::Array(self.items))
    }
}

impl ser::SerializeTuple for SeqBuilder {
    type Ok = Value;
    type Error = CanonicalError;

    fn serialize_element<T: ?Sized + Serialize>(
        &mut self,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.push(value)
    }

    fn end(self) -> Result<Value, CanonicalError> {
        Ok(Value::Array(self.items))
    }
}

impl ser::SerializeTupleStruct for SeqBuilder {
    type Ok = Value;
    type Error = CanonicalError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CanonicalError> {
        self.push(value)
    }

    fn end(self) -> Result<Value, CanonicalError> {
        Ok(Value::Array(self.items))
    }
}

struct TupleVariantBuilder {
    variant: &'static str,
    items: Vec<Value>,
}

impl ser::SerializeTupleVariant for TupleVariantBuilder {
    type Ok = Value;
    type Error = CanonicalError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CanonicalError> {
        self.items.push(value.serialize(ValueSerializer)?);
        Ok(())
    }

    fn end(self) -> Result<Value, CanonicalError> {
        Ok(Value::Object(vec![ObjectEntry {
            key: self.variant.to_string(),
            value: Value::Array(self.items),
        }]))
    }
}

/// Retain typed entries until sorted emission to avoid pre-encoding nested byte buffers.
struct MapBuilder {
    entries: Vec<ObjectEntry>,
    pending_key: Option<String>,
    variant: Option<&'static str>,
}

impl MapBuilder {
    fn new(len: Option<usize>, variant: Option<&'static str>) -> Self {
        Self {
            entries: Vec::with_capacity(len.unwrap_or(0)),
            pending_key: None,
            variant,
        }
    }

    fn push_entry<T: ?Sized + Serialize>(
        &mut self,
        key: String,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.entries.push(ObjectEntry {
            key,
            value: value.serialize(ValueSerializer)?,
        });
        Ok(())
    }

    fn finish(self) -> Value {
        let object = Value::Object(self.entries);
        match self.variant {
            Some(variant) => Value::Object(vec![ObjectEntry {
                key: variant.to_string(),
                value: object,
            }]),
            None => object,
        }
    }
}

impl ser::SerializeMap for MapBuilder {
    type Ok = Value;
    type Error = CanonicalError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), CanonicalError> {
        let mut collector = KeyCollector { key: String::new() };
        key.serialize(&mut collector)?;
        self.pending_key = Some(collector.key);
        Ok(())
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), CanonicalError> {
        let key = self
            .pending_key
            .take()
            .ok_or_else(|| ser::Error::custom("map value serialized without a key"))?;
        self.push_entry(key, value)
    }

    fn end(self) -> Result<Value, CanonicalError> {
        Ok(self.finish())
    }
}

impl ser::SerializeStruct for MapBuilder {
    type Ok = Value;
    type Error = CanonicalError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.push_entry(key.to_string(), value)
    }

    fn end(self) -> Result<Value, CanonicalError> {
        Ok(self.finish())
    }
}

impl ser::SerializeStructVariant for MapBuilder {
    type Ok = Value;
    type Error = CanonicalError;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.push_entry(key.to_string(), value)
    }

    fn end(self) -> Result<Value, CanonicalError> {
        Ok(self.finish())
    }
}

/// Match serde_json's scalar map-key conversions; reject types without a string representation.
struct KeyCollector {
    key: String,
}

impl ser::Serializer for &mut KeyCollector {
    type Ok = ();
    type Error = CanonicalError;
    type SerializeSeq = ser::Impossible<(), CanonicalError>;
    type SerializeTuple = ser::Impossible<(), CanonicalError>;
    type SerializeTupleStruct = ser::Impossible<(), CanonicalError>;
    type SerializeTupleVariant = ser::Impossible<(), CanonicalError>;
    type SerializeMap = ser::Impossible<(), CanonicalError>;
    type SerializeStruct = ser::Impossible<(), CanonicalError>;
    type SerializeStructVariant = ser::Impossible<(), CanonicalError>;

    fn serialize_bool(self, v: bool) -> Result<(), CanonicalError> {
        self.key.push_str(if v { "true" } else { "false" });
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> Result<(), CanonicalError> {
        self.key.push_str(&i64::from(v).to_string());
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> Result<(), CanonicalError> {
        self.key.push_str(&i64::from(v).to_string());
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> Result<(), CanonicalError> {
        self.key.push_str(&i64::from(v).to_string());
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> Result<(), CanonicalError> {
        self.key.push_str(&v.to_string());
        Ok(())
    }

    fn serialize_i128(self, v: i128) -> Result<(), CanonicalError> {
        self.key.push_str(&v.to_string());
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> Result<(), CanonicalError> {
        self.key.push_str(&u64::from(v).to_string());
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> Result<(), CanonicalError> {
        self.key.push_str(&u64::from(v).to_string());
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> Result<(), CanonicalError> {
        self.key.push_str(&u64::from(v).to_string());
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> Result<(), CanonicalError> {
        self.key.push_str(&v.to_string());
        Ok(())
    }

    fn serialize_u128(self, v: u128) -> Result<(), CanonicalError> {
        self.key.push_str(&v.to_string());
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> Result<(), CanonicalError> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<(), CanonicalError> {
        if !v.is_finite() {
            return Err(CanonicalError::NonFiniteNumber { offset: 0 });
        }
        let Some(number) = serde_json::Number::from_f64(v) else {
            return Err(CanonicalError::NonFiniteNumber { offset: 0 });
        };
        self.key.push_str(&number.to_string());
        Ok(())
    }

    fn serialize_char(self, v: char) -> Result<(), CanonicalError> {
        self.key.push(v);
        Ok(())
    }

    fn serialize_str(self, v: &str) -> Result<(), CanonicalError> {
        self.key.push_str(v);
        Ok(())
    }

    fn serialize_bytes(self, _v: &[u8]) -> Result<(), CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_none(self) -> Result<(), CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), CanonicalError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<(), CanonicalError> {
        self.key.push_str(variant);
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<(), CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_seq(
        self,
        _len: Option<usize>,
    ) -> Result<ser::Impossible<(), CanonicalError>, CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_tuple(
        self,
        _len: usize,
    ) -> Result<ser::Impossible<(), CanonicalError>, CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<ser::Impossible<(), CanonicalError>, CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<ser::Impossible<(), CanonicalError>, CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_map(
        self,
        _len: Option<usize>,
    ) -> Result<ser::Impossible<(), CanonicalError>, CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<ser::Impossible<(), CanonicalError>, CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<ser::Impossible<(), CanonicalError>, CanonicalError> {
        Err(ser::Error::custom("map key must be a string"))
    }
}

fn to_strict_value<T: Serialize>(value: &T) -> Result<Value, CanonicalError> {
    value.serialize(ValueSerializer)
}

pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let owned = to_strict_value(value)?;
    canonicalize_value(&owned)
}

pub fn canonicalize_string<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    canonicalize(value).map(|v| String::from_utf8(v).expect("canonical is valid UTF-8"))
}

/// Stream from one typed tree; writer errors may leave a partial document in the destination.
pub fn canonicalize_to_writer<T: Serialize, W: Write>(
    value: &T,
    writer: &mut W,
) -> Result<(), CanonicalError> {
    let owned = to_strict_value(value)?;
    let mut w = CountingWriter {
        inner: writer,
        written: 0,
    };
    write_value(&mut w, &owned)
}

pub(crate) fn canonicalize_value(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::with_capacity(64);
    {
        let mut w = CountingWriter {
            inner: &mut out,
            written: 0,
        };
        write_value(&mut w, value)?;
    }
    Ok(out)
}

pub fn canonical_hash_hex<T: Serialize>(value: &T) -> Result<HashHex, CanonicalError> {
    let bytes = canonicalize(value)?;
    Ok(HashHex::sha256(&bytes))
}

fn write_value<W: Write>(w: &mut CountingWriter<W>, v: &Value) -> Result<(), CanonicalError> {
    match v {
        Value::Null => w.write_all(b"null").map_err(io_error),
        Value::Bool(true) => w.write_all(b"true").map_err(io_error),
        Value::Bool(false) => w.write_all(b"false").map_err(io_error),
        Value::Int(n) => w.write_all(n.to_string().as_bytes()).map_err(io_error),
        Value::UInt(n) => w.write_all(n.to_string().as_bytes()).map_err(io_error),
        Value::Float(x) => {
            if !x.is_finite() {
                return Err(CanonicalError::NonFiniteNumber { offset: w.written });
            }
            let s = format_float(*x);
            w.write_all(s.as_bytes()).map_err(io_error)
        }
        Value::String(s) => write_string(w, s).map_err(io_error),
        Value::Array(items) => {
            w.write_all(b"[").map_err(io_error)?;
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",").map_err(io_error)?;
                }
                write_value(w, item)?;
            }
            w.write_all(b"]").map_err(io_error)
        }
        Value::Object(entries) => {
            let mut sorted: Vec<&ObjectEntry> = entries.iter().collect();
            sorted.sort_by(|a, b| a.key.cmp(&b.key));
            w.write_all(b"{").map_err(io_error)?;
            for (i, entry) in sorted.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",").map_err(io_error)?;
                }
                write_string(w, &entry.key).map_err(io_error)?;
                w.write_all(b":").map_err(io_error)?;
                write_value(w, &entry.value)?;
            }
            w.write_all(b"}").map_err(io_error)
        }
    }
}

fn write_string<W: Write>(w: &mut W, s: &str) -> std::io::Result<()> {
    w.write_all(b"\"")?;
    for ch in s.chars() {
        let code = ch as u32;
        match ch {
            '"' => w.write_all(b"\\\"")?,
            '\\' => w.write_all(b"\\\\")?,
            '\x08' => w.write_all(b"\\b")?,
            '\x0c' => w.write_all(b"\\f")?,
            '\n' => w.write_all(b"\\n")?,
            '\r' => w.write_all(b"\\r")?,
            '\t' => w.write_all(b"\\t")?,
            c if (c as u32) < 0x20 => {
                let buf = format!("\\u{code:04x}");
                w.write_all(buf.as_bytes())?;
            }
            _ if code >= 0x80 => {
                // Match ensure_ascii=True, using surrogate pairs for characters above U+FFFF.
                if code <= 0xFFFF {
                    let buf = format!("\\u{code:04x}");
                    w.write_all(buf.as_bytes())?;
                } else {
                    let high = 0xD800 + ((code - 0x10000) >> 10);
                    let low = 0xDC00 + ((code - 0x10000) & 0x3FF);
                    let buf = format!("\\u{high:04x}\\u{low:04x}");
                    w.write_all(buf.as_bytes())?;
                }
            }
            c => {
                let mut buf = [0u8; 4];
                let s = c.encode_utf8(&mut buf);
                w.write_all(s.as_bytes())?;
            }
        }
    }
    w.write_all(b"\"")
}

/// Preserve Python float spelling: trailing .0 for integers and signed, padded exponents.
pub(crate) fn format_float(x: f64) -> String {
    debug_assert!(
        x.is_finite(),
        "non-finite values must be rejected before formatting"
    );
    if x == 0.0 {
        return if x.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }
    let s = format!("{x}");
    if s.contains('.') || s.contains('e') || s.contains('E') {
        return fixup_exponent(&s);
    }
    format!("{s}.0")
}

fn fixup_exponent(s: &str) -> String {
    let e_pos = match s.find(['e', 'E']) {
        Some(p) => p,
        None => return s.to_string(),
    };
    let (mantissa, exp) = s.split_at(e_pos);
    let exp_body = &exp[1..]; // skip 'e'
    let (sign, digits) = if let Some(stripped) = exp_body.strip_prefix('+') {
        ('+', stripped)
    } else if let Some(stripped) = exp_body.strip_prefix('-') {
        ('-', stripped)
    } else {
        ('+', exp_body)
    };
    format!("{mantissa}e{sign}{digits}")
}

#[cfg(test)]
mod tests {
    use super::{canonicalize, canonicalize_to_writer, canonicalize_value, format_float};
    use crate::value::{ObjectEntry, Value};
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::io::{self, Write};

    #[derive(Serialize)]
    struct WithFloat {
        value: f64,
    }

    #[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
    enum Color {
        Red,
        Blue,
    }

    struct EntryMap<K, V> {
        entries: Vec<(K, V)>,
    }

    impl<K: Serialize, V: Serialize> Serialize for EntryMap<K, V> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(self.entries.len()))?;
            for (key, value) in &self.entries {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
    }

    fn serde_json_map_bytes<T: Serialize>(value: &T) -> Vec<u8> {
        let as_value = serde_json::to_value(value).expect("serde_json map serializer");
        serde_json::to_vec(&as_value).expect("serde_json map bytes")
    }

    struct Boom;

    impl Serialize for Boom {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("boom"))
        }
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn write_all(&mut self, _buf: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Accepts a bounded number of bytes, then fails: the streaming path
    /// must surface the failure as `Io`, never as a number error.
    struct PartialWriter {
        remaining: usize,
    }

    impl Write for PartialWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            let taken = buf.len().min(self.remaining);
            self.remaining -= taken;
            Ok(taken)
        }

        fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
            if buf.len() > self.remaining {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.remaining -= buf.len();
            Ok(())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Non-finite numbers are rejected before any null conversion, writer
    /// failures surface as a distinct `Io` error, serde-level rejections
    /// surface as a distinct `Serialize` error, and the streamed writer
    /// path emits exactly the same canonical bytes as the buffered path.
    #[test]
    fn nonfinite_and_io() {
        assert!(matches!(
            canonicalize_value(&Value::Float(f64::NAN)),
            Err(crate::CanonicalError::NonFiniteNumber { offset: 0 })
        ));
        assert!(matches!(
            canonicalize_value(&Value::Array(vec![
                Value::Int(1),
                Value::Float(f64::INFINITY)
            ])),
            Err(crate::CanonicalError::NonFiniteNumber { offset: 3 })
        ));
        assert!(matches!(
            canonicalize(&WithFloat { value: f64::NAN }),
            Err(crate::CanonicalError::NonFiniteNumber { .. })
        ));
        assert_eq!(format_float(0.0), "0.0");

        assert!(matches!(
            canonicalize_to_writer(&vec![1u64, 2, 3], &mut BrokenWriter),
            Err(crate::CanonicalError::Io { .. })
        ));
        assert!(matches!(
            canonicalize_to_writer(&vec![1u64, 2, 3], &mut PartialWriter { remaining: 3 }),
            Err(crate::CanonicalError::Io { .. })
        ));

        assert!(matches!(
            canonicalize(&Boom),
            Err(crate::CanonicalError::Serialize { message }) if message.contains("boom")
        ));
        // A key type the canonical vocabulary cannot represent is a
        // `Serialize` rejection, not an I/O or number failure.
        assert!(matches!(
            canonicalize(&BTreeMap::<Option<u8>, u8>::from([(None, 1)])),
            Err(crate::CanonicalError::Serialize { .. })
        ));

        let mut unit_keys = BTreeMap::new();
        unit_keys.insert(Color::Blue, 2u8);
        unit_keys.insert(Color::Red, 1u8);
        assert_eq!(
            canonicalize(&unit_keys).expect("unit-enum map keys"),
            br#"{"Blue":2,"Red":1}"#,
            "unit-enum map keys match serde_json::to_value string names"
        );

        let float_keys = EntryMap {
            entries: vec![
                (1.0f64, 1u8),
                (1.5f64, 2u8),
                (1e5f64, 3u8),
                (-0.0f64, 4u8),
                (1e-5f64, 5u8),
            ],
        };
        assert_eq!(
            canonicalize(&float_keys).expect("float map keys"),
            serde_json_map_bytes(&float_keys),
            "float map keys match pinned serde_json Number/map-serializer bytes"
        );
        assert!(matches!(
            canonicalize(&EntryMap {
                entries: vec![(f64::NAN, 1u8)]
            }),
            Err(crate::CanonicalError::NonFiniteNumber { .. })
        ));

        let mut i128_keys = BTreeMap::new();
        i128_keys.insert(i128::MIN, 1u8);
        i128_keys.insert(i128::MAX, 2u8);
        i128_keys.insert(u64::MAX as i128 + 1, 3u8);
        assert_eq!(
            canonicalize(&i128_keys).expect("i128 map keys"),
            serde_json_map_bytes(&i128_keys),
            "i128 map keys keep full decimal names"
        );

        let mut u128_keys = BTreeMap::new();
        u128_keys.insert(0u128, 1u8);
        u128_keys.insert(u128::MAX, 2u8);
        u128_keys.insert(u64::MAX as u128 + 1, 3u8);
        assert_eq!(
            canonicalize(&u128_keys).expect("u128 map keys"),
            serde_json_map_bytes(&u128_keys),
            "u128 map keys keep full decimal names"
        );

        assert_eq!(
            canonicalize(&(i64::MAX as i128 + 1)).expect("i128 value above i64"),
            b"9223372036854775808"
        );
        assert_eq!(
            canonicalize(&(u64::MAX as i128)).expect("i128 value at u64 max"),
            b"18446744073709551615"
        );
        assert!(matches!(
            canonicalize(&(u64::MAX as i128 + 1)),
            Err(crate::CanonicalError::Serialize { .. })
        ));
        assert!(matches!(
            canonicalize(&(i64::MIN as i128 - 1)),
            Err(crate::CanonicalError::Serialize { .. })
        ));
        assert_eq!(
            canonicalize(&(u64::MAX as u128)).expect("u128 value at u64 max"),
            b"18446744073709551615"
        );
        assert!(matches!(
            canonicalize(&(u64::MAX as u128 + 1)),
            Err(crate::CanonicalError::Serialize { .. })
        ));

        let value = Value::Object(vec![
            ObjectEntry {
                key: "b".to_string(),
                value: Value::Int(2),
            },
            ObjectEntry {
                key: "a".to_string(),
                value: Value::String("é😀".to_string()),
            },
        ]);
        let buffered = canonicalize(&value).expect("canonicalizes");
        assert_eq!(
            buffered, br#"{"a":"\u00e9\ud83d\ude00","b":2}"#,
            "keys stay sorted and surrogates stay lowercase"
        );
        let mut streamed = Vec::new();
        canonicalize_to_writer(&value, &mut streamed).expect("streams");
        assert_eq!(buffered, streamed);

        assert_eq!(
            canonicalize(&u64::MAX).expect("canonicalizes"),
            b"18446744073709551615".to_vec()
        );
        assert_eq!(
            canonicalize(&1.5f64).expect("canonicalizes"),
            b"1.5".to_vec()
        );
        assert_eq!(
            canonicalize(&1.0f64).expect("canonicalizes"),
            b"1.0".to_vec()
        );
        assert_eq!(
            canonicalize(&1e5f64).expect("canonicalizes"),
            b"100000.0".to_vec()
        );
        assert_eq!(
            canonicalize(&-0.0f64).expect("canonicalizes"),
            b"-0.0".to_vec()
        );
    }
}
