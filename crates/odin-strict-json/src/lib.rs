//! Reject duplicate keys before typed decoding and encode canonical JSON for stable hashes.

#![deny(unsafe_code)]
#![deny(dead_code)]
#![deny(unused)]

mod canonical;
mod error;
mod parse;
mod value;

pub use canonical::{
    canonical_hash_hex, canonicalize, canonicalize_string, canonicalize_to_writer, CanonicalError,
};
pub use error::{DecodeError, DecodeOptions};
pub use parse::{decode, decode_with_options, parse};
pub use value::{ObjectEntry, Value};
