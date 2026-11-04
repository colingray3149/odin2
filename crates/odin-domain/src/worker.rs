//! Worker phases and invocation identities shared by the process manager, ledger, and kernel.

use std::fmt;

use odin_types::hash::{hex_decode, hex_encode};
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
        if raw.len() != INVOCATION_ID_HEX_LEN {
            return Err(InvocationIdError::WrongLength);
        }
        let decoded = hex_decode(raw).map_err(|_| InvocationIdError::NotLowerHex)?;
        decoded
            .try_into()
            .map(Self)
            .map_err(|_| InvocationIdError::WrongLength)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The canonical lowercase hex encoding (32 chars).
    pub fn to_hex(self) -> String {
        hex_encode(&self.0)
    }
}

impl fmt::Display for InvocationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
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

#[cfg(test)]
mod tests {
    use super::{can_transition_worker, InvocationId, InvocationIdError, WorkerPhase};

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
