//! Worker phases and invocation identities shared by the process manager, ledger, and kernel.

use std::fmt;

use odin_types::WorkerId;
use serde::{Deserialize, Serialize};

/// The systemd-assigned 128-bit InvocationID identifies one scope creation
/// even when unit names or PIDs are reused.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InvocationId([u8; 16]);

pub const INVOCATION_ID_HEX_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationIdError {
    WrongLength,
    NotLowerHex,
}

impl fmt::Display for InvocationIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => formatter.write_str("invocation id must be exactly 16 bytes"),
            Self::NotLowerHex => formatter.write_str("invocation id must be lowercase hex"),
        }
    }
}

impl std::error::Error for InvocationIdError {}

impl InvocationId {
    pub fn from_raw(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Decodes the canonical lowercase hex encoding (32 chars).
    pub fn from_hex(raw: &str) -> Result<Self, InvocationIdError> {
        let bytes = raw.as_bytes();
        if bytes.len() != INVOCATION_ID_HEX_LEN {
            return Err(InvocationIdError::WrongLength);
        }
        let mut decoded = [0_u8; 16];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let high = hex_digit(pair[0]).ok_or(InvocationIdError::NotLowerHex)?;
            let low = hex_digit(pair[1]).ok_or(InvocationIdError::NotLowerHex)?;
            decoded[index] = (high << 4) | low;
        }
        Ok(Self(decoded))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The canonical lowercase hex encoding (32 chars).
    pub fn to_hex(self) -> String {
        let mut hex = String::with_capacity(INVOCATION_ID_HEX_LEN);
        for byte in self.0 {
            hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble fits hex"));
            hex.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("nibble fits hex"));
        }
        hex
    }
}

impl fmt::Display for InvocationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 0x0A),
        _ => None,
    }
}

/// Durable worker phases. The canonical strings are the wire spellings and
/// the `worker_registry.state` values.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerPhase {
    /// Intent is recorded before scope creation.
    Registered,
    /// Scope identity is confirmed, but the payload has not been released.
    ScopeCreated,
    /// Payload released into the scope.
    PayloadRunning,
    /// No surviving unit, cgroup, or process remains.
    Stopped,
    /// The worker failed before or during the payload and holds no residue.
    Failed,
    /// Unit, cgroup, or process residue remains and is recorded.
    Residual,
}

impl WorkerPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::ScopeCreated => "scope_created",
            Self::PayloadRunning => "payload_running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Residual => "residual",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "registered" => Some(Self::Registered),
            "scope_created" => Some(Self::ScopeCreated),
            "payload_running" => Some(Self::PayloadRunning),
            "stopped" => Some(Self::Stopped),
            "failed" => Some(Self::Failed),
            "residual" => Some(Self::Residual),
            _ => None,
        }
    }

    /// Terminal phases never move again.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed | Self::Residual)
    }

    /// Nonterminal phases block their correlation identity until reconciled.
    pub fn is_nonterminal(self) -> bool {
        !self.is_terminal()
    }
}

impl fmt::Display for WorkerPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Allowed worker phase transitions; terminal phases cannot transition.
pub fn can_transition_worker(from: WorkerPhase, to: WorkerPhase) -> bool {
    use WorkerPhase::*;
    matches!(
        (from, to),
        (Registered, ScopeCreated)
            | (Registered, Failed)
            | (ScopeCreated, PayloadRunning)
            | (ScopeCreated, Failed)
            | (ScopeCreated, Residual)
            | (PayloadRunning, Stopped)
            | (PayloadRunning, Failed)
            | (PayloadRunning, Residual)
    )
}

/// Worker scope identity and cgroup/process anchors; `/proc` correlation is
/// supplemental and does not authorize control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRecord {
    pub worker_id: WorkerId,
    pub unit: String,
    pub invocation_id: Option<InvocationId>,
    pub correlation_id: String,
    pub tx_id: String,
    pub wp_id: String,
    pub attempt: u32,
    pub cgroup_path: Option<String>,
    pub cgroup_inode: Option<u64>,
    pub leader_pid: Option<u32>,
    pub leader_start_ticks: Option<u64>,
    pub phase: WorkerPhase,
}

#[cfg(test)]
mod tests {
    use super::{
        can_transition_worker, InvocationId, InvocationIdError, WorkerPhase, INVOCATION_ID_HEX_LEN,
    };

    #[test]
    fn invocation_id_hex_roundtrip() {
        let raw = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let invocation = InvocationId::from_raw(raw);
        let hex = invocation.to_hex();
        assert_eq!(hex.len(), INVOCATION_ID_HEX_LEN);
        assert_eq!(hex, "0123456789abcdeffedcba9876543210");
        assert_eq!(InvocationId::from_hex(&hex), Ok(invocation));
        assert_eq!(invocation.as_bytes(), &raw);
        assert_eq!(invocation.to_string(), hex);
    }

    #[test]
    fn invocation_id_rejects_wrong_shape() {
        assert_eq!(
            InvocationId::from_hex("0102"),
            Err(InvocationIdError::WrongLength)
        );
        assert_eq!(
            InvocationId::from_hex(&"0".repeat(31)),
            Err(InvocationIdError::WrongLength)
        );
        assert_eq!(
            InvocationId::from_hex(&"Z".repeat(32)),
            Err(InvocationIdError::NotLowerHex)
        );
        assert_eq!(
            InvocationId::from_hex(&"A".repeat(32)),
            Err(InvocationIdError::NotLowerHex)
        );
        assert!(InvocationId::from_hex(&"0".repeat(32)).is_ok());
    }

    #[test]
    fn worker_phase_strings_are_canonical() {
        let phases = [
            (WorkerPhase::Registered, "registered"),
            (WorkerPhase::ScopeCreated, "scope_created"),
            (WorkerPhase::PayloadRunning, "payload_running"),
            (WorkerPhase::Stopped, "stopped"),
            (WorkerPhase::Failed, "failed"),
            (WorkerPhase::Residual, "residual"),
        ];
        for (phase, canonical) in phases {
            assert_eq!(phase.as_str(), canonical);
            assert_eq!(phase.to_string(), canonical);
            assert_eq!(WorkerPhase::parse(canonical), Some(phase));
            let serialized = serde_json::to_string(&phase).expect("serialize phase");
            assert_eq!(serialized, format!("\"{canonical}\""));
            assert_eq!(
                serde_json::from_str::<WorkerPhase>(&serialized).expect("parse phase"),
                phase
            );
        }
        assert_eq!(WorkerPhase::parse("running"), None);
        assert_eq!(WorkerPhase::parse(""), None);
    }

    #[test]
    fn worker_transition_law_is_exact() {
        use WorkerPhase::*;
        let legal = [
            (Registered, ScopeCreated),
            (Registered, Failed),
            (ScopeCreated, PayloadRunning),
            (ScopeCreated, Failed),
            (ScopeCreated, Residual),
            (PayloadRunning, Stopped),
            (PayloadRunning, Failed),
            (PayloadRunning, Residual),
        ];
        for (from, to) in legal {
            assert!(
                can_transition_worker(from, to),
                "{from} -> {to} must be legal"
            );
        }
        let phases = [
            Registered,
            ScopeCreated,
            PayloadRunning,
            Stopped,
            Failed,
            Residual,
        ];
        for from in phases {
            for to in phases {
                if legal.contains(&(from, to)) {
                    continue;
                }
                assert!(
                    !can_transition_worker(from, to),
                    "{from} -> {to} must be illegal"
                );
            }
            assert!(
                !can_transition_worker(from, from),
                "{from} -> {from} must be illegal"
            );
        }
        for terminal in [Stopped, Failed, Residual] {
            assert!(terminal.is_terminal());
            assert!(!terminal.is_nonterminal());
            for to in phases {
                assert!(
                    !can_transition_worker(terminal, to),
                    "terminal {terminal} must never move to {to}"
                );
            }
        }
        for nonterminal in [Registered, ScopeCreated, PayloadRunning] {
            assert!(nonterminal.is_nonterminal());
            assert!(!nonterminal.is_terminal());
        }
    }
}
