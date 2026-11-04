use std::os::unix::net::UnixStream;
use std::path::Path;

use odin_sidecar_protocol::{
    read_response, write_request, Arguments, Budget, Request, Response, WireLimits,
};
use odin_types::{CapsuleId, CorrelationId, ToolId};

use crate::{SidecarError, SidecarErrorCode};

/// Convenience methods convert rejections to errors; `request` preserves the wire response.
pub struct SidecarClient {
    stream: UnixStream,
    limits: WireLimits,
}

impl SidecarClient {
    pub fn connect(socket_path: &Path, limits: WireLimits) -> Result<Self, SidecarError> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|error| SidecarError::filesystem(socket_path, error))?;
        Ok(Self { stream, limits })
    }

    pub fn invoke_capability(
        &mut self,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        capability: ToolId,
        budget: Budget,
        arguments: Arguments,
    ) -> Result<Response, SidecarError> {
        self.exchange(Request::InvokeCapability {
            wire: odin_sidecar_protocol::Version,
            capsule_id,
            correlation_id,
            capability,
            budget,
            arguments,
        })
    }

    /// Return rejections as data so callers can inspect the full protocol response.
    pub fn request(&mut self, request: Request) -> Result<Response, SidecarError> {
        write_request(&mut self.stream, &request, self.limits)?;
        let unanswered = |detail: String| SidecarError::new(SidecarErrorCode::Unanswered, detail);
        read_response(&mut self.stream, self.limits)
            .map_err(|error| unanswered(error.to_string()))?
            .ok_or_else(|| unanswered("server closed without a response".to_owned()))
    }

    fn exchange(&mut self, request: Request) -> Result<Response, SidecarError> {
        let response = self.request(request)?;
        match response {
            Response::Rejected { code, detail, .. } => Err(SidecarError::new(
                SidecarErrorCode::Remote,
                format!("{}: {detail}", code.as_str()),
            )),
            response => Ok(response),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// A server that takes the request and hangs up leaves the caller unable to say the effect did not land.
    #[test]
    fn a_hangup_after_the_request_is_unanswered_not_refused() {
        let dir = tempfile::tempdir().expect("socket directory");
        let path = dir.path().join("authority.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let limits = odin_sidecar_protocol::WireLimits::new(4096, 8192).expect("limits");
            odin_sidecar_protocol::read_request(&mut stream, limits).expect("the request arrives");
        });
        let mut client = SidecarClient::connect(
            &path,
            odin_sidecar_protocol::WireLimits::new(4096, 8192).expect("limits"),
        )
        .expect("connect");
        let error = client
            .request(Request::CloseCapsule {
                wire: odin_sidecar_protocol::Version,
                capsule_id: CapsuleId::new("capsule-hangup").expect("capsule id"),
                correlation_id: CorrelationId::new("00112233445566778899aabbccddeeff")
                    .expect("correlation id"),
                mode: odin_sidecar_protocol::CloseMode::Drain,
            })
            .expect_err("no answer");
        server.join().expect("server");
        assert_eq!(error.code(), SidecarErrorCode::Unanswered, "{error}");
    }
}
