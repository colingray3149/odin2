//! The authenticated command seam: command ports that carry the verified
//! device identity alongside the ordinary protocol request.

use std::future::Future;

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

pub struct FunctionCommandPort<F> {
    function: F,
}

impl<F> FunctionCommandPort<F> {
    pub fn new(function: F) -> Self {
        Self { function }
    }
}

#[async_trait]
impl<F, O> HuginnCommandPort for FunctionCommandPort<F>
where
    F: Fn(HuginnRequest) -> O + Send + Sync,
    O: Future<Output = Result<HuginnResponse, HuginnProtocolError>> + Send,
{
    async fn execute(&self, request: HuginnRequest) -> Result<HuginnResponse, HuginnProtocolError> {
        (self.function)(request).await
    }
}

pub struct AuthenticatedFunctionCommandPort<F, A> {
    function: F,
    authenticated_function: A,
}

impl<F, A> AuthenticatedFunctionCommandPort<F, A> {
    pub fn new(function: F, authenticated_function: A) -> Self {
        Self {
            function,
            authenticated_function,
        }
    }
}

#[async_trait]
impl<F, A, O> HuginnCommandPort for AuthenticatedFunctionCommandPort<F, A>
where
    F: Fn(HuginnRequest) -> O + Send + Sync,
    O: Future<Output = Result<HuginnResponse, HuginnProtocolError>> + Send,
    A: Send + Sync,
{
    async fn execute(&self, request: HuginnRequest) -> Result<HuginnResponse, HuginnProtocolError> {
        (self.function)(request).await
    }
}

#[async_trait]
impl<F, A, O, AO> AuthenticatedCommandPort for AuthenticatedFunctionCommandPort<F, A>
where
    F: Fn(HuginnRequest) -> O + Send + Sync,
    O: Future<Output = Result<HuginnResponse, HuginnProtocolError>> + Send,
    A: Fn(DeviceId, HuginnRequest) -> AO + Send + Sync,
    AO: Future<Output = Result<HuginnResponse, HuginnProtocolError>> + Send,
{
    async fn execute_authenticated(
        &self,
        device: DeviceId,
        request: HuginnRequest,
    ) -> Result<HuginnResponse, HuginnProtocolError> {
        (self.authenticated_function)(device, request).await
    }
}
