//! Keep hex encoding local to avoid another dependency.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    WrongLength { expected: usize, actual: usize },
    OddLength(usize),
    BadChar(char),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::WrongLength { expected, actual } => {
                write!(f, "expected {expected} hex chars, got {actual}")
            }
            HashError::OddLength(n) => write!(f, "hex length {n} is odd"),
            HashError::BadChar(c) => write!(f, "non-hex character {c:?}"),
        }
    }
}

impl std::error::Error for HashError {}

pub const SHA256_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HashHex(String);

impl HashHex {
    pub fn from_hex(s: &str) -> Result<Self, HashError> {
        if s.len() != SHA256_HEX_LEN {
            return Err(HashError::WrongLength {
                expected: SHA256_HEX_LEN,
                actual: s.len(),
            });
        }
        for ch in s.chars() {
            if !matches!(ch, '0'..='9' | 'a'..='f') {
                return Err(HashError::BadChar(ch));
            }
        }
        Ok(Self(s.to_string()))
    }

    pub fn sha256(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(bytes);
        Self(hex_encode(&h.finalize()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HashHex {
    type Error = HashError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex(&value)
    }
}

impl From<HashHex> for String {
    fn from(value: HashHex) -> Self {
        value.0
    }
}

impl AsRef<str> for HashHex {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HashHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn sha256_hex(bytes: &[u8]) -> HashHex {
    HashHex::sha256(bytes)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, HashError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HashError::OddLength(bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, HashError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(HashError::BadChar(b as char)),
    }
}
