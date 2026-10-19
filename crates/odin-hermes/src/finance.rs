//! Monthly finance summaries read directly from an Actual Budget SQLite file in read-only mode.
//!
//! Queries use Actual's transaction/category tables and integer `YYYYMMDD` dates and `YYYYMM` months.
//! Summaries exclude account details, notes, and payees. Oversized categories fail rather than truncate.
//! The budget path comes from configuration; missing or unsupported budgets return typed unavailability.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use odin_domain::envelope::EventEnvelopeInit;
use odin_domain::{Actor, Correlation, DomainError, EventEnvelope, Producer, Redaction, Scope};
use rusqlite::{Connection, OpenFlags};
use serde_json::json;

/// Identifies the source of every summary.
pub const FINANCE_SOURCE_ACTUAL_BUDGET: &str = "actual-budget";

pub const FINANCE_SUMMARY_EVENT_KIND: &str = "odin.finance.summary";

/// At most this many distinct categories appear in one summary; a budget
/// exceeding the bound fails the summary instead of being truncated.
const MAX_CATEGORY_ROWS: usize = 64;

const MAX_CATEGORY_NAME_BYTES: usize = 128;

/// Deployment facts for the finance adapter, supplied by operator
/// configuration. There is no default path anywhere in this crate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinanceDeployment {
    budget_db_path: PathBuf,
}

impl FinanceDeployment {
    /// Creates a deployment from an absolute budget database path. Relative
    /// paths are refused as unconfigured: the adapter never guesses where a
    /// budget lives.
    pub fn new(budget_db_path: impl Into<PathBuf>) -> Result<Self, FinanceError> {
        let budget_db_path = budget_db_path.into();
        if !budget_db_path.is_absolute() {
            return Err(FinanceError::Unavailable(FinanceUnavailable::NotConfigured));
        }
        Ok(Self { budget_db_path })
    }

    pub fn budget_db_path(&self) -> &Path {
        &self.budget_db_path
    }
}

/// The summary window: one calendar month, parsed from the canonical
/// `YYYY-MM` wire form and carried also in the integer forms Actual stores
/// (`YYYYMM` for budget months, `YYYYMMDD` day bounds for transaction
/// dates).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinanceMonth {
    raw: String,
    month_key: i64,
    first_day: i64,
    last_day: i64,
}

impl FinanceMonth {
    /// Parses `YYYY-MM`. The day bounds deliberately span 01..=31: no real
    /// month exceeds 31 days, so the upper bound never clips a real date.
    pub fn parse(raw: &str) -> Result<Self, FinanceError> {
        let invalid = || FinanceError::InvalidMonth;
        let bytes = raw.as_bytes();
        if bytes.len() != 7 || bytes[4] != b'-' {
            return Err(invalid());
        }
        if !bytes[..4].iter().all(u8::is_ascii_digit) || !bytes[5..].iter().all(u8::is_ascii_digit)
        {
            return Err(invalid());
        }
        let year: i64 = raw[..4].parse().map_err(|_| invalid())?;
        let month: i64 = raw[5..7].parse().map_err(|_| invalid())?;
        if !(1970..=2099).contains(&year) || !(1..=12).contains(&month) {
            return Err(invalid());
        }
        Ok(Self {
            raw: raw.to_owned(),
            month_key: year * 100 + month,
            first_day: year * 10_000 + month * 100,
            last_day: year * 10_000 + month * 100 + 31,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    fn month_key(&self) -> i64 {
        self.month_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategorySummary {
    pub name: String,
    pub budgeted_cents: i64,
    /// Signed sum of the month's flows into this category: negative for
    /// spending, positive for refunds (Actual's own sign convention).
    pub spent_cents: i64,
}

/// Internal aggregate retaining category identity and income classification.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CategoryAggregate {
    category_id: String,
    name: String,
    is_income: bool,
    amount_sum: i64,
}

/// Monthly aggregates excluding account details, tokens, notes, and payees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinanceSummary {
    pub month: String,
    pub source: &'static str,
    /// Positive inflow magnitude across income categories.
    pub income_cents: i64,
    /// Positive outflow magnitude across expense categories.
    pub spent_cents: i64,
    /// `income_cents - spent_cents`.
    pub net_cents: i64,
    /// Scoped ledger rows considered, independent of categorization.
    pub transaction_count: u64,
    pub categories: Vec<CategorySummary>,
}

impl FinanceSummary {
    /// The allowlisted envelope payload. This is the exact surface a general
    /// event carries for the summary — nothing outside these keys exists.
    pub fn envelope_payload(&self) -> serde_json::Value {
        json!({
            "month": self.month,
            "source": self.source,
            "income_cents": self.income_cents,
            "spent_cents": self.spent_cents,
            "net_cents": self.net_cents,
            "transaction_count": self.transaction_count,
            "categories": self
                .categories
                .iter()
                .map(|category| {
                    json!({
                        "name": category.name,
                        "budgeted_cents": category.budgeted_cents,
                        "spent_cents": category.spent_cents,
                    })
                })
                .collect::<Vec<_>>(),
        })
    }
}

/// Construction input for [`summary_event`], mirroring
/// [`EventEnvelopeInit`] minus the fields the summary fixes itself.
#[derive(Clone, Debug)]
pub struct SummaryEventInit {
    pub id: odin_domain::EventId,
    pub sequence: u64,
    pub revision: u64,
    pub occurred_at_ms: u64,
    pub actor: Actor,
    pub scope: Scope,
    pub producer: Producer,
}

/// Builds the outgoing envelope for one summary. The correlation
/// idempotency key is derived from the month alone, so replaying a summary
/// request for the same month produces the same key (CORE-004) without
/// embedding any account data. The payload is the allowlisted aggregate
/// projection; no fixture account number or token can appear because the
/// adapter never selects one.
pub fn summary_event(
    summary: &FinanceSummary,
    init: SummaryEventInit,
) -> Result<EventEnvelope, DomainError> {
    let correlation = Correlation::new(format!("finance-summary:{}", summary.month))?;
    let SummaryEventInit {
        id,
        sequence,
        revision,
        occurred_at_ms,
        actor,
        scope,
        producer,
    } = init;
    EventEnvelope::new(EventEnvelopeInit {
        id,
        sequence,
        revision,
        occurred_at_ms,
        kind: FINANCE_SUMMARY_EVENT_KIND.to_owned(),
        actor,
        scope,
        correlation,
        payload: summary.envelope_payload(),
        // The payload is already narrowed to aggregates by construction; the
        // envelope honestly declares no further redaction is needed.
        redaction: Redaction::None,
        producer,
    })
}

/// Why a finance summary genuinely does not exist. These are the typed
/// missing prerequisites; every one is reported instead of any fabricated
/// empty success.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FinanceUnavailable {
    #[error("no budget source is configured")]
    NotConfigured,
    #[error("the configured budget database does not exist")]
    BudgetMissing,
    #[error("the configured file is not an Actual Budget database")]
    NotBudgetDatabase,
    #[error("the budget does not use envelope budgets (zero_budgets is absent)")]
    UnsupportedBudgetType,
}

/// Every failure a finance summary can produce.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FinanceError {
    #[error("the summary month must be a canonical YYYY-MM in 1970-01..=2099-12")]
    InvalidMonth,
    #[error("the finance source is unavailable: {0}")]
    Unavailable(#[from] FinanceUnavailable),
    /// Static sanitized reason: budget contents never enter an error.
    #[error("the budget could not be summarized: {0}")]
    Query(&'static str),
}

/// Read-only adapter over one Actual Budget database file.
pub struct ActualBudget {
    connection: Connection,
}

/// The tables the summary depends on, probed before any query runs. Their
/// absence means the file is not an Actual Budget database.
const REQUIRED_TABLES: &[&str] = &[
    "transactions",
    "categories",
    "category_mapping",
    "category_groups",
];

impl ActualBudget {
    /// Opens the configured budget read-only. A missing file is
    /// [`FinanceUnavailable::BudgetMissing`]; a present file without the
    /// required Actual tables is [`FinanceUnavailable::NotBudgetDatabase`];
    /// a database without `zero_budgets` uses a budget type this adapter
    /// does not summarize and is
    /// [`FinanceUnavailable::UnsupportedBudgetType`]. Read-only mode also
    /// guarantees the adapter can never mutate a real budget.
    pub fn open(deployment: &FinanceDeployment) -> Result<Self, FinanceError> {
        let path = deployment.budget_db_path();
        let metadata = std::fs::metadata(path).map_err(|_| FinanceUnavailable::BudgetMissing)?;
        if metadata.is_dir() {
            return Err(FinanceUnavailable::BudgetMissing.into());
        }
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| FinanceUnavailable::NotBudgetDatabase)?;
        let budget = Self { connection };
        budget.probe_tables()?;
        Ok(budget)
    }
    fn probe_tables(&self) -> Result<(), FinanceError> {
        let schema_error = |error: rusqlite::Error| {
            // A file that is not SQLite at all is a foreign file: typed
            // NotBudgetDatabase, not an opaque query failure.
            let not_a_database = matches!(
                error,
                rusqlite::Error::SqliteFailure(failure, _)
                    if failure.extended_code == rusqlite::ffi::SQLITE_NOTADB
            );
            if not_a_database {
                FinanceUnavailable::NotBudgetDatabase.into()
            } else {
                FinanceError::Query("the budget schema is unreadable")
            }
        };
        let present: Vec<String> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT name FROM sqlite_master
                     WHERE type = 'table' AND name IN (?, ?, ?, ?)",
                )
                .map_err(schema_error)?;
            let rows = statement
                .query_map(
                    rusqlite::params![
                        REQUIRED_TABLES[0],
                        REQUIRED_TABLES[1],
                        REQUIRED_TABLES[2],
                        REQUIRED_TABLES[3],
                    ],
                    |row| row.get::<_, String>(0),
                )
                .map_err(schema_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(schema_error)?
        };
        if present.len() != REQUIRED_TABLES.len() {
            return Err(FinanceUnavailable::NotBudgetDatabase.into());
        }
        let zero_budgets: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'zero_budgets'",
                [],
                |row| row.get(0),
            )
            .map_err(schema_error)?;
        if zero_budgets == 0 {
            return Err(FinanceUnavailable::UnsupportedBudgetType.into());
        }
        Ok(())
    }

    /// Summarizes one month. Totals cover every alive, account-bearing,
    /// non-split-parent row in the window; category rows additionally carry
    /// a category that resolves through Actual's `category_mapping` to a
    /// known category. Budgeted amounts come from `zero_budgets` for the
    /// month; a category without a row there is simply not budgeted (zero).
    pub fn month_summary(&self, month: FinanceMonth) -> Result<FinanceSummary, FinanceError> {
        let category_names = self.category_names()?;
        let budgeted = self.budgeted_amounts(month.month_key(), &category_names)?;
        let (transaction_count, aggregates) = self.category_aggregates(&month)?;

        // One summary row per category ID: spending rows from the month's
        // transactions UNION budgeted rows with no flows (a budgeted but
        // unspent category is exactly the observable a subscription
        // summary needs). Duplicate display names stay distinct rows —
        // Actual categories are identified by ID, never by name.
        struct AggregateRow {
            name: String,
            is_income: bool,
            spent_cents: i64,
        }
        let mut by_id: BTreeMap<String, AggregateRow> = BTreeMap::new();
        for row in aggregates {
            by_id.insert(
                row.category_id,
                AggregateRow {
                    name: row.name,
                    is_income: row.is_income,
                    spent_cents: row.amount_sum,
                },
            );
        }
        for category_id in budgeted.keys() {
            by_id.entry(category_id.clone()).or_insert_with(|| {
                let (name, is_income) = category_names[category_id].clone();
                AggregateRow {
                    name,
                    is_income,
                    spent_cents: 0,
                }
            });
        }

        let mut income_total = 0_i64;
        let mut spent_total = 0_i64;
        let mut categories = Vec::with_capacity(by_id.len());
        for (category_id, row) in &by_id {
            if row.name.len() > MAX_CATEGORY_NAME_BYTES {
                return Err(FinanceError::Query(
                    "a category name exceeds the summary bound",
                ));
            }
            if row.is_income {
                income_total += row.spent_cents;
            } else {
                spent_total -= row.spent_cents;
            }
            categories.push(CategorySummary {
                name: row.name.clone(),
                budgeted_cents: budgeted.get(category_id).copied().unwrap_or(0),
                spent_cents: row.spent_cents,
            });
        }
        if categories.len() > MAX_CATEGORY_ROWS {
            return Err(FinanceError::Query(
                "the month spans more categories than the summary bound",
            ));
        }
        // Deterministic wire order: by name, then signed flow.
        categories.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.spent_cents.cmp(&right.spent_cents))
        });

        Ok(FinanceSummary {
            month: month.raw,
            source: FINANCE_SOURCE_ACTUAL_BUDGET,
            income_cents: income_total,
            spent_cents: spent_total,
            net_cents: income_total - spent_total,
            transaction_count,
            categories,
        })
    }

    /// `id -> (name, is_income)` for every category, tombstones included:
    /// historical months legitimately reference retired categories, and
    /// Actual's own views keep them joinable.
    fn category_names(&self) -> Result<HashMap<String, (String, bool)>, FinanceError> {
        const QUERY: &str = "SELECT id, name, IFNULL(is_income, 0) FROM categories";
        const UNREADABLE: FinanceError = FinanceError::Query("categories are unreadable");
        let mut statement = self.connection.prepare(QUERY).map_err(|_| UNREADABLE)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? != 0,
                ))
            })
            .map_err(|_| UNREADABLE)?;
        let mut names = HashMap::new();
        for row in rows {
            let (id, name, is_income) = row.map_err(|_| UNREADABLE)?;
            names.insert(id, (name, is_income));
        }
        Ok(names)
    }

    /// Budgeted minor-unit amounts for one month, keyed by category ID —
    /// never by display name, which Actual does not guarantee unique.
    /// Budget rows pointing at unknown categories mean the budget file and
    /// its categories disagree — a typed failure, never silently folded in.
    fn budgeted_amounts(
        &self,
        month_key: i64,
        category_names: &HashMap<String, (String, bool)>,
    ) -> Result<HashMap<String, i64>, FinanceError> {
        const QUERY: &str = "SELECT category, IFNULL(amount, 0) FROM zero_budgets WHERE month = ?";
        const UNREADABLE: FinanceError = FinanceError::Query("budget amounts are unreadable");
        let mut statement = self.connection.prepare(QUERY).map_err(|_| UNREADABLE)?;
        let rows = statement
            .query_map(rusqlite::params![month_key], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|_| UNREADABLE)?;
        let mut budgeted = HashMap::new();
        for row in rows {
            let (category_id, amount) = row.map_err(|_| UNREADABLE)?;
            if !category_names.contains_key(&category_id) {
                return Err(FinanceError::Query(
                    "a budgeted amount references an unknown category",
                ));
            }
            budgeted.insert(category_id, amount);
        }
        Ok(budgeted)
    }

    /// The month's scoped rows: count over every alive, account-bearing,
    /// non-split-parent transaction in the window, plus the per-category-ID
    /// aggregates. Category rows resolve `transactions.category` through
    /// `category_mapping` exactly as Actual's own transaction views do; a
    /// scoped category that resolves to nothing is a typed failure.
    fn category_aggregates(
        &self,
        month: &FinanceMonth,
    ) -> Result<(u64, Vec<CategoryAggregate>), FinanceError> {
        const UNREADABLE: FinanceError = FinanceError::Query("transactions are unreadable");
        const TOTALS: &str = "
            SELECT COUNT(*)
            FROM transactions
            WHERE IFNULL(tombstone, 0) = 0
              AND acct IS NOT NULL
              AND IFNULL(isParent, 0) = 0
              AND date >= ? AND date <= ?";
        let row_count: i64 = self
            .connection
            .query_row(
                TOTALS,
                rusqlite::params![month.first_day, month.last_day],
                |row| row.get(0),
            )
            .map_err(|_| UNREADABLE)?;

        const GROUPED: &str = "
            SELECT cm.transferId AS category_id,
                   IFNULL(c.name, '') AS category_name,
                   IFNULL(c.is_income, 0) AS is_income,
                   SUM(IFNULL(t.amount, 0)) AS amount_sum
            FROM transactions t
            LEFT JOIN category_mapping cm ON cm.id = t.category
            LEFT JOIN categories c ON c.id = cm.transferId
            WHERE IFNULL(t.tombstone, 0) = 0
              AND t.acct IS NOT NULL
              AND IFNULL(t.isParent, 0) = 0
              AND t.date >= ? AND t.date <= ?
              AND t.category IS NOT NULL
            GROUP BY category_id
            ORDER BY category_id";
        let mut statement = self.connection.prepare(GROUPED).map_err(|_| UNREADABLE)?;
        let rows = statement
            .query_map(rusqlite::params![month.first_day, month.last_day], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|_| UNREADABLE)?;

        let mut aggregates = Vec::new();
        for row in rows {
            let (category_id, name, is_income, amount_sum) = row.map_err(|_| UNREADABLE)?;
            let Some(category_id) = category_id else {
                return Err(FinanceError::Query(
                    "a scoped transaction references an unknown category",
                ));
            };
            if name.is_empty() {
                return Err(FinanceError::Query(
                    "a scoped transaction references an unknown category",
                ));
            }
            aggregates.push(CategoryAggregate {
                category_id,
                name,
                is_income,
                amount_sum,
            });
        }
        Ok((
            u64::try_from(row_count).map_err(|_| UNREADABLE)?,
            aggregates,
        ))
    }
}
