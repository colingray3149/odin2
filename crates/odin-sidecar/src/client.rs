use std::os::unix::net::UnixStream;
use std::path::Path;

use odin_sidecar_protocol::{
    read_response, write_request, Arguments, Budget, CloseMode, Request, Response, WireLimits,
};
use odin_types::{CapsuleId, CorrelationId, OperationId, ToolId};

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

    pub fn resume_operation(
        &mut self,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: OperationId,
    ) -> Result<Response, SidecarError> {
        self.exchange(Request::ResumeOperation {
            wire: odin_sidecar_protocol::Version,
            capsule_id,
            correlation_id,
            operation_id,
        })
    }

    pub fn reconcile_operation(
        &mut self,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: OperationId,
    ) -> Result<Response, SidecarError> {
        self.exchange(Request::ReconcileOperation {
            wire: odin_sidecar_protocol::Version,
            capsule_id,
            correlation_id,
            operation_id,
        })
    }

    pub fn close_capsule(
        &mut self,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        mode: CloseMode,
    ) -> Result<Response, SidecarError> {
        self.exchange(Request::CloseCapsule {
            wire: odin_sidecar_protocol::Version,
            capsule_id,
            correlation_id,
            mode,
        })
    }

    pub fn stop_intent(
        &mut self,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        operation_id: Option<OperationId>,
    ) -> Result<Response, SidecarError> {
        self.exchange(Request::StopIntent {
            wire: odin_sidecar_protocol::Version,
            capsule_id,
            correlation_id,
            operation_id,
        })
    }

    /// Return rejections as data so callers can inspect the full protocol response.
    pub fn request(&mut self, request: Request) -> Result<Response, SidecarError> {
        write_request(&mut self.stream, &request, self.limits)?;
        read_response(&mut self.stream, self.limits)?.ok_or_else(|| {
            SidecarError::new(
                SidecarErrorCode::Protocol,
                "server closed without a response",
            )
        })
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
