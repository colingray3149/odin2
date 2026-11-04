use odin_domain::huginn::HuginnMessage;

use super::codec::{decode_frame, encode_frame, redacted_json, CodecError, CodecLimits, Versioned};
use super::ServerFrame;

pub fn encode_message(
    message: &HuginnMessage,
    limits: &CodecLimits,
) -> Result<Vec<u8>, CodecError> {
    encode_frame(&ServerFrame::General(message.clone()), limits)
}

pub fn decode_message(
    frame: &[u8],
    limits: &CodecLimits,
) -> Result<Versioned<HuginnMessage>, CodecError> {
    let decoded = decode_frame::<ServerFrame>(frame, limits)?;
    match decoded.value {
        ServerFrame::General(message) => Ok(Versioned {
            version: decoded.version,
            value: message,
        }),
        ServerFrame::Live(_) => Err(CodecError::Malformed {
            code: "expectedGeneralMessage",
        }),
    }
}

pub fn redacted_message_json(
    message: &HuginnMessage,
    limits: &CodecLimits,
) -> Result<serde_json::Value, CodecError> {
    redacted_json(message, limits)
}
