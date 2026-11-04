//! Account availability, transport, approval, and ledger errors.

use odin_domain::ApprovalId;

use serde::Serialize;
use std::fmt;

/// An unavailable account-side prerequisite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountUnavailable {
    /// The account selector names no configured account.
    Account,
    /// The account's sops-rendered credential is missing or unreadable.
    Credentials,
    /// The account service could not be reached at all.
    Service,
}

impl fmt::Display for AccountUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Account => "the requested life account is not configured",
            Self::Credentials => "the account credential is unavailable",
            Self::Service => "the account service is unavailable",
        };
        formatter.write_str(message)
    }
}

/// A fault of one account transport exchange. The static message names
/// the failure; a `*Detail` variant adds the underlying cause.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportFault {
    Unavailable(AccountUnavailable),
    /// An unavailable prerequisite with the failure that made it so.
    UnavailableDetail {
        unavailable: AccountUnavailable,
        detail: String,
    },
    /// Rejects the account, capability, or expiry before an exchange starts.
    Refused(&'static str),
    /// A refusal with its cause.
    RefusedDetail {
        message: &'static str,
        detail: String,
    },
    /// The exchange could not be completed as the standard protocol
    /// requires; the static message names the shape failure only.
    Protocol(&'static str),
    /// A protocol failure with its cause.
    ProtocolDetail {
        message: &'static str,
        detail: String,
    },
    /// The service rejected the exchange with this HTTP status.
    Rejected {
        message: &'static str,
        status: u16,
    },
    /// The exchange exceeded its configured deadline. Whether the
    /// request reached the service is unknowable from here.
    Timeout,
}
impl fmt::Display for TransportFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(unavailable) => write!(formatter, "{unavailable}"),
            Self::UnavailableDetail {
                unavailable,
                detail,
            } => write!(formatter, "{unavailable}: {detail}"),
            Self::Refused(message) | Self::Protocol(message) => formatter.write_str(message),
            Self::RefusedDetail { message, detail } | Self::ProtocolDetail { message, detail } => {
                write!(formatter, "{message}: {detail}")
            }
            Self::Rejected { message, status } => write!(formatter, "{message}: HTTP {status}"),
            Self::Timeout => formatter.write_str("the account exchange exceeded its deadline"),
        }
    }
}

impl std::error::Error for TransportFault {}

impl TransportFault {
    pub fn unavailable(unavailable: AccountUnavailable, cause: impl fmt::Display) -> Self {
        Self::UnavailableDetail {
            unavailable,
            detail: cause.to_string(),
        }
    }

    pub fn refused(message: &'static str, cause: impl fmt::Display) -> Self {
        Self::RefusedDetail {
            message,
            detail: cause.to_string(),
        }
    }

    pub fn protocol(message: &'static str, cause: impl fmt::Display) -> Self {
        Self::ProtocolDetail {
            message,
            detail: cause.to_string(),
        }
    }

    /// Whether the payload was not sent, allowing a recorded effect to settle as failed.
    /// Timeouts and malformed replies leave the outcome unknown and must not trigger retries.
    pub const fn proves_not_dispatched(&self) -> bool {
        matches!(
            self,
            Self::Unavailable(_)
                | Self::UnavailableDetail { .. }
                | Self::Refused(_)
                | Self::RefusedDetail { .. }
        )
    }
}

/// Successfully applied ids in application order and the fault that stopped the batch.
/// A nonempty `applied` list indicates partial execution; the remainder may be unresolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchFault {
    pub applied: Vec<String>,
    pub fault: TransportFault,
}

impl BatchFault {
    pub fn after(applied: Vec<String>, fault: TransportFault) -> Self {
        Self { applied, fault }
    }
}

impl From<TransportFault> for BatchFault {
    fn from(fault: TransportFault) -> Self {
        Self {
            applied: Vec::new(),
            fault,
        }
    }
}

impl fmt::Display for BatchFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.fault)
    }
}

impl std::error::Error for BatchFault {}

/// Why a credential lease could not be issued or used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeaseRejection {
    /// No account is configured under the requested selector.
    UnknownAccount,
    /// The account's credential reference is not currently available, and why.
    CredentialsUnavailable(String),
    Expired,
    /// The lease binds a different account or capability.
    ScopeMismatch,
}

impl fmt::Display for LeaseRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownAccount => "no lease source knows this account",
            Self::CredentialsUnavailable(detail) => {
                return write!(
                    formatter,
                    "the lease source cannot resolve the credential: {detail}"
                )
            }
            Self::Expired => "the credential lease has expired",
            Self::ScopeMismatch => "the credential lease does not bind this operation",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LeaseRejection {}

/// The sanitized record of one operator denial. Carries identifiers
/// only — the approved-scope digest lives on the durable approval, and
/// no effect content is ever attached.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialRecord {
    pub approval_id: ApprovalId,
    pub evidence_ref: String,
    pub decided_by: String,
}

/// A typed mirror of the kernel approval redirects a gated effect can
/// observe. None of these outcomes reaches a transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateRedirect {
    NeedsApproval { approval_id: Option<ApprovalId> },
    AlreadyApproved { approval_id: ApprovalId },
    Expired { approval_id: ApprovalId },
    Cancelled { approval_id: ApprovalId },
    NotFound { approval_id: ApprovalId },
}

/// Coarse ledger failure class. Ledger error text may embed internal
/// ids; the life surface deliberately reports only the class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerFailure {
    /// The durable store could not be reached or its lock is poisoned.
    Unavailable,
    /// The store refused the operation as invalid.
    Invalid,
}

/// Errors returned by life operations, excluding message content and credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifeError {
    InvalidInput(&'static str),
    /// Invalid input with its cause.
    InvalidInputDetail {
        message: &'static str,
        detail: String,
    },
    Unavailable(AccountUnavailable),
    /// An unavailable prerequisite with the failure that made it so.
    UnavailableDetail {
        unavailable: AccountUnavailable,
        detail: String,
    },
    Timeout,
    Gate(GateRedirect),
    Denied(DenialRecord),
    /// The dispatch outcome is unknowable (deadline exceeded, malformed
    /// reply after dispatch). The effect may have landed; it is never
    /// retried or re-recorded from here.
    InDoubt,
    /// An in-doubt outcome with the failure that left it so.
    InDoubtDetail {
        detail: String,
    },
    /// Applied ids are stored beside the in-doubt command; the unresolved remainder is not retried.
    PartiallyApplied {
        known_ids: Vec<String>,
    },
    /// A transport protocol failure with a static sanitized message.
    Protocol(&'static str),
    /// A protocol failure with its cause.
    ProtocolDetail {
        message: &'static str,
        detail: String,
    },
    /// The service rejected the exchange with this HTTP status.
    Rejected {
        message: &'static str,
        status: u16,
    },
    Ledger {
        class: LedgerFailure,
        detail: String,
    },
}

impl fmt::Display for LifeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::InvalidInputDetail { message, detail } => {
                write!(formatter, "{message}: {detail}")
            }
            Self::Unavailable(unavailable) => write!(formatter, "{unavailable}"),
            Self::UnavailableDetail {
                unavailable,
                detail,
            } => write!(formatter, "{unavailable}: {detail}"),
            Self::Timeout => formatter.write_str("the account exchange exceeded its deadline"),
            Self::Gate(redirect) => write!(formatter, "the approval gate redirected: {redirect:?}"),
            Self::Denied(denial) => write!(
                formatter,
                "the operator denied approval {} (evidence {})",
                denial.approval_id, denial.evidence_ref
            ),
            Self::InDoubt => {
                formatter.write_str("the effect dispatch outcome is unknowable; reconcile first")
            }
            Self::InDoubtDetail { detail } => write!(
                formatter,
                "the effect dispatch outcome is unknowable ({detail}); reconcile first"
            ),
            Self::PartiallyApplied { known_ids } => write!(
                formatter,
                "the effect partially applied (known ids: {known_ids:?}); the remainder is \
                 unknowable; reconcile first"
            ),
            Self::Protocol(message) => formatter.write_str(message),
            Self::ProtocolDetail { message, detail } => write!(formatter, "{message}: {detail}"),
            Self::Rejected { message, status } => write!(formatter, "{message}: HTTP {status}"),
            Self::Ledger { class, detail } => {
                write!(formatter, "the durable ledger failed ({class:?}): {detail}")
            }
        }
    }
}

impl std::error::Error for LifeError {}

impl LifeError {
    pub fn invalid(message: &'static str, cause: impl fmt::Display) -> Self {
        Self::InvalidInputDetail {
            message,
            detail: cause.to_string(),
        }
    }

    pub fn protocol(message: &'static str, cause: impl fmt::Display) -> Self {
        Self::ProtocolDetail {
            message,
            detail: cause.to_string(),
        }
    }
}
