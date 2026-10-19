//! Huginn/ColinRemote wire protocol.

pub mod codec;
mod request;
mod response;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "channel", content = "value")]
pub enum ClientFrame {
    Live(odin_domain::huginn::LiveClientRequest),
    General(odin_domain::huginn::HuginnRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "channel", content = "value")]
pub enum ServerFrame {
    Live(odin_domain::huginn::LiveServerMessage),
    General(odin_domain::huginn::HuginnMessage),
}

pub use codec::{
    canonical_bytes, decode, decode_frame, encode, encode_frame, redacted_json, CodecError,
    CodecLimits, Versioned, PROTOCOL_VERSION,
};
pub use request::{arguments_digest, decode_request, encode_request, redacted_request_json};
pub use response::{decode_message, encode_message, redacted_message_json};
