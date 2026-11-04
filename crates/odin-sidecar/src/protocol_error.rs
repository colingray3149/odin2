use odin_sidecar_protocol::ProtocolError;

use crate::{SidecarError, SidecarErrorCode};

impl From<ProtocolError> for SidecarError {
    fn from(error: ProtocolError) -> Self {
        Self::new(SidecarErrorCode::Protocol, error.to_string())
    }
}
