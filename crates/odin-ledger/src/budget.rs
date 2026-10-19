//! Transactional integer USD-micros reservation and reconciliation.

use odin_registry::ResolvedBudgetPolicy;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Ledger, LedgerError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetReservationRequest {
    pub reservation_id: String,
    pub request_id: String,
    pub policy: ResolvedBudgetPolicy,
    pub amount_usd_micros: u64,
    pub logical_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetReconciliationRequest {
    pub request_id: String,
    pub actual_usd_micros: u64,
    pub logical_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDisposition {
    Eligible,
    Exhausted { eligible_at: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetStatus {
    pub scope: String,
    pub window_start: u64,
    pub window_end: u64,
    pub policy_revision: u64,
    pub policy_digest: odin_domain::Digest,
    pub limit_usd_micros: u64,
    pub reserved_usd_micros: u64,
    pub reconciled_usd_micros: u64,
    pub revision: u64,
    pub disposition: BudgetDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetReservation {
    pub reservation_id: String,
    pub request_id: String,
    pub scope: String,
    pub window_start: u64,
    pub policy_digest: odin_domain::Digest,
    pub reserved_usd_micros: u64,
    pub reconciled_usd_micros: Option<u64>,
    pub created_logical: u64,
    pub reconciled_logical: Option<u64>,
    pub revision: u64,
    pub status: BudgetStatus,
}

#[derive(Debug, Error)]
pub enum BudgetError {
    #[error("invalid budget request: {0}")]
    Invalid(String),
    #[error("budget request {request_id:?} conflicts with an existing reservation")]
    DuplicateConflict { request_id: String },
    #[error("budget exhausted for {status_scope} until logical time {eligible_at}")]
    Exhausted {
        status_scope: String,
        eligible_at: u64,
        status: Box<BudgetStatus>,
    },
    #[error("budget reservation for request {0:?} was not found")]
    NotFound(String),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
}

pub fn budget_status(
    ledger: &Ledger,
    scope: &str,
    window_start: u64,
    policy_digest: odin_domain::Digest,
) -> Result<Option<BudgetStatus>, BudgetError> {
    status_row(ledger.connection(), scope, window_start, policy_digest).map_err(BudgetError::Ledger)
}

fn status_row(
    connection: &Connection,
    scope: &str,
    window_start: u64,
    digest: odin_domain::Digest,
) -> Result<Option<BudgetStatus>, LedgerError> {
    let row=connection.query_row("SELECT window_end,policy_revision,limit_usd_micros,reserved_usd_micros,reconciled_usd_micros,status,revision FROM budget_accounts WHERE scope=?1 AND window_start=?2 AND policy_digest=?3",params![scope,to_i64(window_start)?,digest.to_string()],|row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,String>(5)?,row.get::<_,i64>(6)?))).optional()?;
    row.map(|row| {
        let end = from_i64(row.0)?;
        Ok(BudgetStatus {
            scope: scope.to_owned(),
            window_start,
            window_end: end,
            policy_revision: from_i64(row.1)?,
            policy_digest: digest,
            limit_usd_micros: from_i64(row.2)?,
            reserved_usd_micros: from_i64(row.3)?,
            reconciled_usd_micros: from_i64(row.4)?,
            revision: from_i64(row.6)?,
            disposition: if row.5 == "eligible" {
                BudgetDisposition::Eligible
            } else {
                BudgetDisposition::Exhausted { eligible_at: end }
            },
        })
    })
    .transpose()
}

fn to_i64(value: u64) -> Result<i64, LedgerError> {
    i64::try_from(value).map_err(|error| {
        LedgerError::invalid_data_caused_by("unsigned budget value exceeds SQLite INTEGER", error)
    })
}
fn from_i64(value: i64) -> Result<u64, LedgerError> {
    u64::try_from(value).map_err(|error| {
        LedgerError::invalid_data_caused_by("negative budget value in ledger", error)
    })
}
