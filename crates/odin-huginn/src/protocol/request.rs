use odin_domain::huginn::HuginnRequest;
use odin_domain::Digest;

use super::codec::{
    canonical_bytes, decode_frame, encode_frame, redacted_json, CodecError, CodecLimits, Versioned,
};
use super::ClientFrame;

pub fn encode_request(
    request: &HuginnRequest,
    limits: &CodecLimits,
) -> Result<Vec<u8>, CodecError> {
    encode_frame(&ClientFrame::General(request.clone()), limits)
}

pub fn decode_request(
    frame: &[u8],
    limits: &CodecLimits,
) -> Result<Versioned<HuginnRequest>, CodecError> {
    let decoded = decode_frame::<ClientFrame>(frame, limits)?;
    match decoded.value {
        ClientFrame::General(request) => Ok(Versioned {
            version: decoded.version,
            value: request,
        }),
        ClientFrame::Live(_) => Err(CodecError::Malformed {
            code: "expectedGeneralRequest",
        }),
    }
}

pub fn arguments_digest(request: &HuginnRequest) -> Result<Digest, CodecError> {
    let bytes = canonical_bytes(request, &CodecLimits::default())?;
    Ok(Digest::hash(&bytes))
}

pub fn redacted_request_json(
    request: &HuginnRequest,
    limits: &CodecLimits,
) -> Result<serde_json::Value, CodecError> {
    redacted_json(request, limits)
}
