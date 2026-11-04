use std::fs;
use std::io::Read as _;
use std::time::{SystemTime, UNIX_EPOCH};

use odin_domain::huginn::LiveSessionId;
use odin_domain::CommandId;

/// Unpredictable bytes from the operating system entropy source. Provisioning
/// never derives secrets from repository content, time, or identity material.
pub fn os_random_bytes(length: usize) -> Result<Vec<u8>, String> {
    let mut source = fs::File::open("/dev/urandom")
        .map_err(|error| format!("could not open the OS entropy source: {error}"))?;
    let mut bytes = vec![0u8; length];
    source
        .read_exact(&mut bytes)
        .map_err(|error| format!("could not read OS entropy: {error}"))?;
    Ok(bytes)
}

/// Parses the operator's command identity as one canonical non-nil UUID.
pub fn parse_command_uuid(raw: &str) -> Result<CommandId, String> {
    LiveSessionId::parse(raw).map_err(|error| {
        format!("invalid command ID {raw:?}; expected a lowercase canonical non-nil UUID: {error}")
    })?;
    CommandId::new(raw).map_err(|error| format!("invalid command ID {raw:?}: {error}"))
}

/// Generates a random canonical v4 UUID for an unpinned operator command.
pub fn random_command_uuid() -> Result<CommandId, String> {
    parse_command_uuid(&uuid::Uuid::new_v4().to_string())
}

pub(super) fn unix_millis() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|error| format!("system time {millis} ms does not fit u64: {error}"))
}
