//! Huginn/Remote client: the wire protocol and the device client.
//!
//! Split out of `odin-huginn` so the phone app can build it; `odin-huginn` re-exports both modules.

pub mod client;
mod peer;
pub mod protocol;

pub use crate::client::{ClientError, RemoteClient, DeviceCredentialStore, LiveConnection};
pub use crate::peer::VerifiedTailnetPeer;
