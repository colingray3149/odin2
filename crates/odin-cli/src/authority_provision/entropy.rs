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

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn push_hex_byte(encoded: &mut String, byte: u8) {
    encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
    encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
}

pub fn hex_string(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        push_hex_byte(&mut encoded, *byte);
    }
    encoded
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
    let random = os_random_bytes(16)?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&random);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut raw = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            raw.push('-');
        }
        push_hex_byte(&mut raw, byte);
    }
    parse_command_uuid(&raw)
}

pub(super) fn unix_millis() -> Result<u64, String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| "system time does not fit u64 milliseconds".to_owned())
}
