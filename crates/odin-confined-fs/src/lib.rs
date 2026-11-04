//! Separate read and write capabilities keep sealed roots read-only at the type level.

#![forbid(unsafe_code)]

mod atomic;
mod capability;
mod error;
mod identity;
mod path;
mod walk;

pub use capability::{Capability, GeneratedCapability, PrivateCapability};
pub use error::{map_io_error, ConfinedError};
pub use identity::{Identity, StatInfo};
pub use path::validate_relative_path;
