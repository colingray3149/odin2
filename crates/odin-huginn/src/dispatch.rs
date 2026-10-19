//! Authenticated transport dispatch: device-scoped connection ownership in
//! `registry`, the verified-device command seam in `command`, and the
//! bounded general/live dispatcher — its per-connection serve loop in
//! `live` and its per-request routing and subscription semantics in
//! `routes`.

mod command;
mod live;
mod outbound;
mod registry;
mod routes;
#[cfg(test)]
mod tests;

pub use command::{
    AuthenticatedCommandPort, AuthenticatedFunctionCommandPort, FunctionCommandPort,
};
pub use live::{DispatchError, DispatchGuard, LiveDispatcher, LiveDispatcherLimits, LiveGateways};
pub use registry::{
    ConnectionFrame, ConnectionRegistration, ConnectionRegistry, FrameReader, FrameWriter,
    RegistryError, ServerConnection,
};
