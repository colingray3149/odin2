use std::fmt;
use std::io;
use std::path::Path;

use odin_kernel::OperationRejection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidecarErrorCode {
    Protocol,
    Filesystem,
    State,
    Authority,
    LegacyImport,
    UnknownOperation,
    ReceiptMissing,
    ReceiptMismatch,
    PeerMismatch,
    Remote,
    Lifecycle,
    LockPoisoned,
}

impl SidecarErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "sidecar.protocol",
            Self::Filesystem => "sidecar.filesystem",
            Self::State => "sidecar.state",
            Self::Authority => "sidecar.authority",
            Self::LegacyImport => "sidecar.legacy_import",
            Self::UnknownOperation => "sidecar.unknown_operation",
            Self::ReceiptMissing => "sidecar.receipt_missing",
            Self::ReceiptMismatch => "sidecar.receipt_mismatch",
            Self::PeerMismatch => "sidecar.peer_mismatch",
            Self::Remote => "sidecar.remote",
            Self::Lifecycle => "sidecar.lifecycle",
            Self::LockPoisoned => "sidecar.lock_poisoned",
        }
    }
}

#[derive(Debug)]
pub struct SidecarError {
    code: SidecarErrorCode,
    detail: String,
}

impl SidecarError {
    pub fn new(code: SidecarErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub(crate) fn filesystem(path: &Path, error: io::Error) -> Self {
        Self::new(
            SidecarErrorCode::Filesystem,
            format!("{}: {error}", path.display()),
        )
    }

    pub(crate) fn poisoned() -> Self {
        Self::new(
            SidecarErrorCode::LockPoisoned,
            "authority store lock was poisoned",
        )
    }

    pub const fn code(&self) -> SidecarErrorCode {
        self.code
    }

    pub const fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for SidecarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.detail)
    }
}

impl std::error::Error for SidecarError {}

impl From<OperationRejection> for SidecarError {
    fn from(rejection: OperationRejection) -> Self {
        let code = match &rejection {
            OperationRejection::UnknownOperation { .. } => SidecarErrorCode::UnknownOperation,
            OperationRejection::Durable(_) => SidecarErrorCode::State,
            _ => SidecarErrorCode::Authority,
        };
        Self::new(code, rejection.to_string())
    }
}

impl From<odin_ledger::LedgerError> for SidecarError {
    fn from(error: odin_ledger::LedgerError) -> Self {
        Self::new(SidecarErrorCode::State, error.to_string())
    }
}
