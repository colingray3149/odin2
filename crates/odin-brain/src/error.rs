//! Error taxonomy for `odin-brain`.
//!
//! `BrainError` wraps the existing authorities instead of inventing parallel
//! ones: `odin_domain::DomainError` for envelope, scope, and transition
//! violations; `odin_atlas::AtlasError` for source and index building;
//! `odin_ledger::LedgerError` for ledger-backed operations. Missing
//! infrastructure must fail honestly via [`BrainError::Unavailable`] rather
//! than fall back to fake success.

use odin_atlas::AtlasError;
use odin_domain::DomainError;
use odin_ledger::LedgerError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrainError {
    /// Domain vocabulary violation (scope, envelope, token, transition).
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// Atlas source/index failure while building or reading pinned revisions.
    #[error(transparent)]
    Atlas(#[from] AtlasError),
    /// Ledger-backed operation failure (audit, approvals, durable state).
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// Brain-local storage failure (index or archive stores).
    #[error("brain storage operation failed: {0}")]
    Storage(#[from] rusqlite::Error),
    /// The brain's PostgreSQL store failed a query that was not an
    /// outage; every construction classifies through
    /// [`BrainError::postgres`], which lifts infrastructure failures into
    /// [`BrainError::Unavailable`].
    #[error("brain postgres operation failed: {0}")]
    Postgres(sqlx::Error),
    #[error("brain serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// A brain policy resolved from registry TOML is invalid.
    #[error("invalid brain policy: {0}")]
    InvalidPolicy(String),
    /// A request violates a brain contract the domain types cannot express.
    #[error("invalid brain request: {0}")]
    InvalidRequest(String),
    /// A declared embedding backend is genuinely unavailable at runtime;
    /// typed so retrieval can machine-match instead of string-matching.
    #[error("embedding backend {provider:?} is unavailable: {reason}")]
    EmbeddingUnavailable { provider: String, reason: String },
    /// Stored brain data failed integrity verification (digest/manifest
    /// mismatch); typed so stores fail closed instead of serving tampered
    /// content.
    #[error("brain store {component} is corrupt: {reason}")]
    Corrupt {
        component: &'static str,
        reason: String,
    },
    /// A referenced brain object (item, record) does not exist.
    #[error("{kind} {id} was not found")]
    NotFound { kind: &'static str, id: String },
    /// A pinned authority moved ahead of stored brain state (e.g. the Atlas
    /// head advanced past the served index generation); typed so resolvers
    /// reject stale data instead of serving it.
    #[error("stale brain authority ({authority}): {detail}")]
    StaleAuthority {
        authority: &'static str,
        detail: String,
    },
    /// Required infrastructure is genuinely unavailable; no fallback exists.
    #[error("required brain infrastructure is unavailable ({component}): {reason}")]
    Unavailable {
        component: &'static str,
        reason: String,
    },
}

/// Component name of the brain's PostgreSQL store in
/// [`BrainError::Unavailable`].
pub const POSTGRES_STORE: &str = "postgres";

/// The brain's PostgreSQL store is unreachable: typed so retrieval and
/// warming shed to intact SQLite instead of failing the turn.
pub fn postgres_outage(reason: impl Into<String>) -> BrainError {
    BrainError::Unavailable {
        component: POSTGRES_STORE,
        reason: reason.into(),
    }
}

impl From<sqlx::Error> for BrainError {
    fn from(error: sqlx::Error) -> Self {
        BrainError::postgres(error)
    }
}

impl BrainError {
    /// Classifies a raw `sqlx::Error` from the brain's PostgreSQL store.
    /// A transport I/O failure, pool exhaustion or closure, a crashed
    /// store worker, a query the server cancelled at its configured
    /// timeout, or the server's connection-termination states is an
    /// [`BrainError::Unavailable`] outage callers shed from; every other
    /// error is a [`BrainError::Postgres`] query or schema bug that must
    /// propagate.
    pub fn postgres(error: sqlx::Error) -> BrainError {
        let outage = match &error {
            sqlx::Error::Io(_)
            | sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::WorkerCrashed => true,
            sqlx::Error::Database(database) => {
                connection_terminated(database.code().as_deref())
                    || cancelled_query(database.code().as_deref())
            }
            _ => false,
        };
        if outage {
            postgres_outage(error.to_string())
        } else {
            BrainError::Postgres(error)
        }
    }

    /// Whether this error is the brain's PostgreSQL store being
    /// unreachable — the one failure that sheds to SQLite. Integrity
    /// (`Corrupt`) and programming errors never match.
    pub fn is_postgres_outage(&self) -> bool {
        matches!(
            self,
            BrainError::Unavailable {
                component: POSTGRES_STORE,
                ..
            }
        )
    }
}

/// SQLSTATEs that mean the connection or server is gone — the connection
/// exception class, the connection limit, and the shutdown states — not
/// that the query was wrong.
fn connection_terminated(code: Option<&str>) -> bool {
    code.is_some_and(|code| {
        code.starts_with("08") || matches!(code, "53300" | "57P01" | "57P02" | "57P03")
    })
}

/// SQLSTATEs of a statement the server refused to keep running: `57014`
/// (query_canceled) is the brain store's `statement_timeout` (postgres
/// `SESSION`) or an operator's `pg_cancel_backend`; `55P03`
/// (lock_not_available) is its `lock_timeout` expiring on a contended
/// lock. Both are the outage callers shed to SQLite on, never corruption
/// or a query bug; malformed SQL keeps its own states and stays a typed
/// [`BrainError::Postgres`].
fn cancelled_query(code: Option<&str>) -> bool {
    matches!(code, Some("57014") | Some("55P03"))
}

pub type BrainResult<T> = Result<T, BrainError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::error::Error as StdError;

    /// A stand-in database error carrying one SQLSTATE: the driver type
    /// is not constructible outside a live connection.
    struct State(&'static str);

    impl std::fmt::Debug for State {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::fmt::Display for State {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl StdError for State {}

    impl sqlx::error::DatabaseError for State {
        fn message(&self) -> &str {
            "state"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.0))
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn state(code: &'static str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(State(code)))
    }

    #[test]
    fn infrastructure_failures_classify_as_outages() {
        let outages = [
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "socket gone",
            )),
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
            sqlx::Error::WorkerCrashed,
            state("08003"),
            state("08006"),
            state("53300"),
            state("57P01"),
            state("57P02"),
            state("57P03"),
            state("57014"),
            state("55P03"),
        ];
        for error in outages {
            let classified = BrainError::postgres(error);
            assert!(
                classified.is_postgres_outage(),
                "{classified:?} must classify as an outage"
            );
        }
    }

    #[test]
    fn query_and_data_errors_stay_postgres() {
        let bugs = [
            state("42P01"),
            state("23505"),
            state("42601"),
            sqlx::Error::RowNotFound,
            sqlx::Error::ColumnNotFound("digest".to_owned()),
        ];
        for error in bugs {
            let classified = BrainError::postgres(error);
            assert!(
                matches!(classified, BrainError::Postgres(_)),
                "{classified:?} must stay a typed postgres bug"
            );
            assert!(!classified.is_postgres_outage());
        }
    }

    #[test]
    fn other_failures_never_match_the_outage() {
        assert!(!BrainError::Corrupt {
            component: "postgres",
            reason: "no chunk at ordinal 0".to_owned(),
        }
        .is_postgres_outage());
        assert!(!BrainError::Unavailable {
            component: "retrieval",
            reason: "policy".to_owned(),
        }
        .is_postgres_outage());
    }
}
