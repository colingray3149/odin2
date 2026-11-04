//! Connect only to the configured Unix socket to avoid ambient bus discovery or autolaunch.

mod codec;
mod endpoint;
mod framing;
mod manager;
mod units;

pub(crate) mod values;

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub(crate) use codec::message_body_start;
pub use codec::{
    decode_body, marshal_method_call, marshal_value, parse_message, Message, Value,
    MESSAGE_KIND_ERROR, MESSAGE_KIND_METHOD_CALL, MESSAGE_KIND_METHOD_RETURN, MESSAGE_KIND_SIGNAL,
};
pub use endpoint::BusAddress;
pub(crate) use endpoint::BusError;
pub use framing::ManagerClient;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use framing::SASL_LINE_BYTES;
pub(crate) use manager::{compose_scope_unit_name, KILL_MODE_CONTROL_GROUP, UNIT_INTERFACE};
#[cfg(any(test, feature = "test-support"))]
pub(crate) use manager::{SCOPE_INTERFACE, SERVICE_INTERFACE};
pub use units::{failed_units, unit_state, ManagerScope};

#[cfg(test)]
use codec::WireCursor;
