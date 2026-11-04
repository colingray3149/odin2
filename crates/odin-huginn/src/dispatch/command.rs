//! The authenticated command seam: a command port that carries the verified
//! device identity alongside the ordinary protocol request.

use async_trait::async_trait;
use odin_domain::huginn::{
    DeviceId, HuginnCommandPort, HuginnProtocolError, HuginnRequest, HuginnResponse,
};

#[async_trait]
pub trait AuthenticatedCommandPort: HuginnCommandPort {
    async fn execute_authenticated(
        &self,
        device: DeviceId,
        request: HuginnRequest,
    ) -> Result<HuginnResponse, HuginnProtocolError>;
}
