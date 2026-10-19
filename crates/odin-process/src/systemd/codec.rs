//! Encode and decode the D-Bus types used by the systemd manager client.

use super::endpoint::{BusError, PROTOCOL_ERROR_NAME};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Byte(u8),
    Bool(bool),
    Int32(i32),
    Uint32(u32),
    Uint64(u64),
    String(String),
    ObjectPath(String),
    Signature(String),
    /// `a<element>` where the inner string is the complete element signature.
    Array(String, Vec<Value>),
    Struct(Vec<Value>),
    Variant(Box<Value>),
}

impl Value {
    pub fn signature(&self) -> String {
        match self {
            Self::Byte(_) => "y".to_owned(),
            Self::Bool(_) => "b".to_owned(),
            Self::Int32(_) => "i".to_owned(),
            Self::Uint32(_) => "u".to_owned(),
            Self::Uint64(_) => "t".to_owned(),
            Self::String(_) => "s".to_owned(),
            Self::ObjectPath(_) => "o".to_owned(),
            Self::Signature(_) => "g".to_owned(),
            Self::Array(element, _) => format!("a{element}"),
            Self::Struct(items) => {
                let mut signature = String::from("(");
                for item in items {
                    signature.push_str(&item.signature());
                }
                signature.push(')');
                signature
            }
            Self::Variant(_) => "v".to_owned(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) | Self::ObjectPath(value) => Some(value),
            _ => None,
        }
    }
}

pub(super) fn signature_alignment(signature: &str) -> Result<usize, BusError> {
    let first = signature
        .chars()
        .next()
        .ok_or_else(|| BusError::new(PROTOCOL_ERROR_NAME, "empty signature"))?;
    Ok(match first {
        'y' | 'g' | 'v' => 1,
        'n' | 'q' => 2,
        'b' | 'i' | 'u' | 's' | 'o' | 'a' => 4,
        'x' | 't' | 'd' | '(' | '{' => 8,
        other => {
            return Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                format!("unsupported signature char {other:?}"),
            ))
        }
    })
}

fn align(buf: &mut Vec<u8>, alignment: usize) {
    let padding = alignment - (buf.len() % alignment);
    if padding != alignment {
        buf.resize(buf.len() + padding, 0);
    }
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn put_signature(buf: &mut Vec<u8>, signature: &str) {
    buf.push(signature.len() as u8);
    buf.extend_from_slice(signature.as_bytes());
    buf.push(0);
}

fn put_string_body(buf: &mut Vec<u8>, value: &str) {
    put_u32(buf, value.len() as u32);
    buf.extend_from_slice(value.as_bytes());
    buf.push(0);
}

fn put_string(buf: &mut Vec<u8>, value: &str) {
    align(buf, 4);
    put_string_body(buf, value);
}

pub fn marshal_value(buf: &mut Vec<u8>, value: &Value) -> Result<(), BusError> {
    match value {
        Value::Byte(inner) => buf.push(*inner),
        Value::Bool(inner) => {
            align(buf, 4);
            put_u32(buf, u32::from(*inner));
        }
        Value::Int32(inner) => {
            align(buf, 4);
            put_u32(buf, *inner as u32);
        }
        Value::Uint32(inner) => {
            align(buf, 4);
            put_u32(buf, *inner);
        }
        Value::Uint64(inner) => {
            align(buf, 8);
            put_u64(buf, *inner);
        }
        Value::String(inner) => put_string(buf, inner),
        Value::ObjectPath(inner) => put_string(buf, inner),
        Value::Signature(inner) => put_signature(buf, inner),
        Value::Array(element, items) => {
            // Array length excludes the padding before its independently aligned element body.
            align(buf, 4);
            let length_slot = buf.len();
            put_u32(buf, 0);
            let element_alignment = signature_alignment(element)?;
            align(buf, element_alignment);
            let start = buf.len();
            for item in items {
                align(buf, element_alignment);
                marshal_value(buf, item)?;
            }
            let encoded = buf.len() - start;
            let length = u32::try_from(encoded)
                .map_err(|_| BusError::new(PROTOCOL_ERROR_NAME, "array body too large"))?;
            buf[length_slot..length_slot + 4].copy_from_slice(&length.to_le_bytes());
        }
        Value::Struct(items) => {
            align(buf, 8);
            for item in items {
                marshal_value(buf, item)?;
            }
        }
        Value::Variant(inner) => {
            put_signature(buf, &inner.signature());
            marshal_value(buf, inner)?;
        }
    }
    Ok(())
}

pub const MESSAGE_KIND_METHOD_CALL: u8 = 1;
pub const MESSAGE_KIND_METHOD_RETURN: u8 = 2;
pub const MESSAGE_KIND_ERROR: u8 = 3;
pub const MESSAGE_KIND_SIGNAL: u8 = 4;

const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_ERROR_NAME: u8 = 4;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SIGNATURE: u8 = 8;

pub fn marshal_method_call(
    serial: u32,
    destination: &str,
    path: &str,
    interface: &str,
    member: &str,
    signature: &str,
    body: &[Value],
) -> Result<Vec<u8>, BusError> {
    if signature.is_empty() != body.is_empty() {
        return Err(BusError::new(
            PROTOCOL_ERROR_NAME,
            "call signature and body disagree",
        ));
    }
    let mut message_body = Vec::new();
    for value in body {
        marshal_value(&mut message_body, value)?;
    }
    let header_field = |code: u8, value: Value| {
        Value::Struct(vec![Value::Byte(code), Value::Variant(Box::new(value))])
    };
    let mut fields = vec![
        header_field(FIELD_PATH, Value::ObjectPath(path.to_owned())),
        header_field(FIELD_INTERFACE, Value::String(interface.to_owned())),
        header_field(FIELD_MEMBER, Value::String(member.to_owned())),
        header_field(FIELD_DESTINATION, Value::String(destination.to_owned())),
    ];
    if !signature.is_empty() {
        fields.push(header_field(
            FIELD_SIGNATURE,
            Value::Signature(signature.to_owned()),
        ));
    }
    let mut message = Vec::with_capacity(message_body.len() + 256);
    message.push(b'l');
    message.push(MESSAGE_KIND_METHOD_CALL);
    message.push(0);
    message.push(1);
    let body_len = u32::try_from(message_body.len())
        .map_err(|_| BusError::new(PROTOCOL_ERROR_NAME, "body too large"))?;
    put_u32(&mut message, body_len);
    put_u32(&mut message, serial);
    // The header array's length occupies bytes 12..16 of the fixed header.
    marshal_value(&mut message, &Value::Array("(yv)".to_owned(), fields))?;
    align(&mut message, 8);
    message.extend_from_slice(&message_body);
    Ok(message)
}

/// Callers decode the raw body against the message signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    pub kind: u8,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub destination: Option<String>,
    pub reply_serial: Option<u32>,
    pub error_name: Option<String>,
    pub signature: String,
    pub body: Vec<u8>,
}

pub fn parse_message(bytes: &[u8]) -> Result<Message, BusError> {
    if bytes.len() < 16 || bytes[0] != b'l' {
        return Err(BusError::new(
            PROTOCOL_ERROR_NAME,
            "message is truncated or not little-endian",
        ));
    }
    let kind = bytes[1];
    let body_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let serial = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let fields_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    // Alignment is relative to the whole message, so retain the array's global offset.
    let mut cursor = WireCursor::with_base(&bytes[12..], 12);
    let fields = cursor.array("(yv)")?;
    if cursor.consumed() != fields_len + 4 {
        return Err(BusError::new(
            PROTOCOL_ERROR_NAME,
            "header-field array length disagrees with the parse",
        ));
    }
    let mut path = None;
    let mut interface = None;
    let mut member = None;
    let mut destination = None;
    let mut reply_serial = None;
    let mut error_name = None;
    let mut signature = String::new();
    for field in &fields {
        let Value::Struct(items) = field else {
            return Err(BusError::new(PROTOCOL_ERROR_NAME, "malformed header field"));
        };
        if items.len() != 2 {
            return Err(BusError::new(PROTOCOL_ERROR_NAME, "malformed header field"));
        }
        let Value::Byte(code) = items[0] else {
            return Err(BusError::new(PROTOCOL_ERROR_NAME, "malformed field code"));
        };
        let Value::Variant(inner) = &items[1] else {
            return Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                "malformed field variant",
            ));
        };
        match code {
            FIELD_PATH => path = inner.as_str().map(str::to_owned),
            FIELD_INTERFACE => interface = inner.as_str().map(str::to_owned),
            FIELD_MEMBER => member = inner.as_str().map(str::to_owned),
            FIELD_DESTINATION => destination = inner.as_str().map(str::to_owned),
            FIELD_ERROR_NAME => error_name = inner.as_str().map(str::to_owned),
            FIELD_REPLY_SERIAL => {
                if let Value::Uint32(value) = inner.as_ref() {
                    reply_serial = Some(*value);
                }
            }
            FIELD_SIGNATURE => {
                if let Value::Signature(value) = inner.as_ref() {
                    signature = value.clone();
                }
            }
            _ => {}
        }
    }
    let body_start = (16 + fields_len + 7) & !7;
    if bytes.len() < body_start + body_len {
        return Err(BusError::new(
            PROTOCOL_ERROR_NAME,
            "message body is truncated",
        ));
    }
    Ok(Message {
        kind,
        serial,
        path,
        interface,
        member,
        destination,
        reply_serial,
        error_name,
        signature,
        body: bytes[body_start..body_start + body_len].to_vec(),
    })
}

pub(super) struct WireCursor<'a> {
    bytes: &'a [u8],
    position: usize,
    base: usize,
}

impl<'a> WireCursor<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self::with_base(bytes, 0)
    }

    fn with_base(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            position: 0,
            base,
        }
    }

    fn consumed(&self) -> usize {
        self.position
    }

    fn align(&mut self, alignment: usize) -> Result<(), BusError> {
        let absolute = self.base + self.position;
        let padding = alignment - (absolute % alignment);
        if padding != alignment {
            if self.bytes.len() < self.position + padding {
                return Err(BusError::new(PROTOCOL_ERROR_NAME, "padding is truncated"));
            }
            self.position += padding;
        }
        Ok(())
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], BusError> {
        if self.bytes.len() < self.position + count {
            return Err(BusError::new(PROTOCOL_ERROR_NAME, "value is truncated"));
        }
        let slice = &self.bytes[self.position..self.position + count];
        self.position += count;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, BusError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, BusError> {
        let raw = self.take(4)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn u64(&mut self) -> Result<u64, BusError> {
        let raw = self.take(8)?;
        Ok(u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]))
    }

    fn string(&mut self) -> Result<String, BusError> {
        self.align(4)?;
        let length = self.u32()? as usize;
        let raw = self.take(length + 1)?;
        if raw[length] != 0 {
            return Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                "string is not terminated",
            ));
        }
        String::from_utf8(raw[..length].to_vec())
            .map_err(|_| BusError::new(PROTOCOL_ERROR_NAME, "string is not UTF-8"))
    }

    fn signature(&mut self) -> Result<String, BusError> {
        let length = self.u8()? as usize;
        let raw = self.take(length + 1)?;
        if raw[length] != 0 {
            return Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                "signature is not terminated",
            ));
        }
        String::from_utf8(raw[..length].to_vec())
            .map_err(|_| BusError::new(PROTOCOL_ERROR_NAME, "signature is not UTF-8"))
    }

    pub(super) fn value(&mut self, signature: &str) -> Result<Value, BusError> {
        let first = signature
            .chars()
            .next()
            .ok_or_else(|| BusError::new(PROTOCOL_ERROR_NAME, "signature ran out mid-value"))?;
        match first {
            'y' => Ok(Value::Byte(self.u8()?)),
            'b' => {
                self.align(4)?;
                let raw = self.u32()?;
                match raw {
                    0 => Ok(Value::Bool(false)),
                    1 => Ok(Value::Bool(true)),
                    other => Err(BusError::new(
                        PROTOCOL_ERROR_NAME,
                        format!("boolean is neither 0 nor 1: {other}"),
                    )),
                }
            }
            'n' | 'q' => {
                self.align(2)?;
                let raw = self.take(2)?;
                let value = u16::from_le_bytes([raw[0], raw[1]]);
                Ok(Value::Int32(i32::from(value)))
            }
            'i' => {
                self.align(4)?;
                Ok(Value::Int32(self.u32()? as i32))
            }
            'u' => {
                self.align(4)?;
                Ok(Value::Uint32(self.u32()?))
            }
            'x' | 't' | 'd' => {
                self.align(8)?;
                Ok(Value::Uint64(self.u64()?))
            }
            's' => Ok(Value::String(self.string()?)),
            'o' => Ok(Value::ObjectPath(self.string()?)),
            'g' => Ok(Value::Signature(self.signature()?)),
            'v' => {
                let inner_signature = self.signature()?;
                let inner = self.value(&inner_signature)?;
                Ok(Value::Variant(Box::new(inner)))
            }
            'a' => {
                let element = complete_type(&signature[1..])?.to_owned();
                // Array length excludes padding before the independently aligned element body.
                self.align(4)?;
                let length = self.u32()? as usize;
                let element_alignment = signature_alignment(&element)?;
                self.align(element_alignment)?;
                let stop = self
                    .position
                    .checked_add(length)
                    .ok_or_else(|| BusError::new(PROTOCOL_ERROR_NAME, "array length overflows"))?;
                if stop > self.bytes.len() {
                    return Err(BusError::new(
                        PROTOCOL_ERROR_NAME,
                        "array body is truncated",
                    ));
                }
                let mut items = Vec::new();
                while self.position < stop {
                    self.align(element_alignment)?;
                    if element.starts_with('{') {
                        let key_signature = dict_key_signature(&element)?;
                        let key = self.value(&key_signature)?;
                        let value_signature = dict_value_signature(&element)?;
                        let value = self.value(&value_signature)?;
                        items.push(Value::Struct(vec![key, value]));
                    } else {
                        items.push(self.value(&element)?);
                    }
                    if self.position > stop {
                        return Err(BusError::new(
                            PROTOCOL_ERROR_NAME,
                            "array element overruns its length",
                        ));
                    }
                }
                Ok(Value::Array(element, items))
            }
            '(' => {
                self.align(8)?;
                let inner = complete_struct_signature(signature)?;
                let mut items = Vec::new();
                let mut rest = inner.as_str();
                while !rest.is_empty() {
                    let one = complete_type(rest)?;
                    items.push(self.value(rest)?);
                    rest = &rest[one.len()..];
                }
                Ok(Value::Struct(items))
            }
            other => Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                format!("unsupported signature char {other:?}"),
            )),
        }
    }

    pub(super) fn array(&mut self, element_signature: &str) -> Result<Vec<Value>, BusError> {
        match self.value(&format!("a{element_signature}"))? {
            Value::Array(_, items) => Ok(items),
            other => Err(BusError::new(
                PROTOCOL_ERROR_NAME,
                format!("expected an array, found {:?}", other.signature()),
            )),
        }
    }
}

/// The complete first type of `signature`, including composite closers and
/// array prefixes.
fn complete_type(signature: &str) -> Result<&str, BusError> {
    let bytes = signature.as_bytes();
    if bytes.is_empty() {
        return Err(BusError::new(PROTOCOL_ERROR_NAME, "empty signature"));
    }
    if bytes[0] == b'a' {
        let inner = complete_type(&signature[1..])?;
        return Ok(&signature[..1 + inner.len()]);
    }
    let mut depth = 0_usize;
    for (index, byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'{' => depth += 1,
            b')' | b'}' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| BusError::new(PROTOCOL_ERROR_NAME, "unbalanced signature"))?;
            }
            _ => {}
        }
        if depth == 0 {
            return Ok(&signature[..index + 1]);
        }
    }
    Err(BusError::new(PROTOCOL_ERROR_NAME, "unbalanced signature"))
}

fn complete_struct_signature(signature: &str) -> Result<String, BusError> {
    signature
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .map(str::to_owned)
        .ok_or_else(|| BusError::new(PROTOCOL_ERROR_NAME, "struct signature is malformed"))
}

fn dict_inner_signature(signature: &str) -> Result<String, BusError> {
    signature
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .map(str::to_owned)
        .ok_or_else(|| BusError::new(PROTOCOL_ERROR_NAME, "dict entry is malformed"))
}

fn dict_key_signature(signature: &str) -> Result<String, BusError> {
    let inner = dict_inner_signature(signature)?;
    Ok(complete_type(&inner)?.to_owned())
}

fn dict_value_signature(signature: &str) -> Result<String, BusError> {
    let inner = dict_inner_signature(signature)?;
    let key = complete_type(&inner)?;
    Ok(inner[key.len()..].to_owned())
}

pub fn decode_body(message: &Message) -> Result<Vec<Value>, BusError> {
    let mut cursor = WireCursor::new(&message.body);
    let mut values = Vec::new();
    let mut rest = message.signature.as_str();
    while !rest.is_empty() {
        let one = complete_type(rest)?;
        values.push(cursor.value(rest)?);
        rest = &rest[one.len()..];
    }
    Ok(values)
}

pub(super) fn decode_error_body(message: &Message) -> String {
    match message.signature.as_str() {
        "s" => decode_body(message)
            .ok()
            .and_then(|values| values.into_iter().next())
            .and_then(|value| match value {
                Value::String(text) => Some(text),
                _ => None,
            })
            .unwrap_or_default(),
        _ => String::new(),
    }
}
