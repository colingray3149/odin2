//! Synthetic life-adapter test fixtures, never runtime input or real personal data.
//!
//! and category-mapping chain. Planted account and token canaries must not appear in outgoing envelopes.

use std::path::Path;

use rusqlite::Connection;
use serde::Deserialize;

pub const FINANCE_FIXTURE_FILE: &str = "finance.json";
pub const EMAIL_FIXTURE_FILE: &str = "email.json";
pub const CALENDAR_FIXTURE_FILE: &str = "calendar.json";

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("fixture IO failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("fixture JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("fixture SQLite write failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("fixture data is invalid: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug)]
pub struct LifeFixtures {
    pub finance: FinanceFixture,
    pub email: EmailFixture,
    pub calendar: CalendarFixture,
}

/// Loads `finance.json`, `email.json`, and `calendar.json` from
/// `fixtures_dir`. Malformed fixture data is a typed failure, never a
/// silently reduced fixture.
pub fn load(fixtures_dir: &Path) -> Result<LifeFixtures, FixtureError> {
    let read_json = |file: &str| -> Result<String, FixtureError> {
        Ok(std::fs::read_to_string(fixtures_dir.join(file))?)
    };
    let finance: FinanceFixture = serde_json::from_str(&read_json(FINANCE_FIXTURE_FILE)?)?;
    let email: EmailFixture = serde_json::from_str(&read_json(EMAIL_FIXTURE_FILE)?)?;
    let calendar: CalendarFixture = serde_json::from_str(&read_json(CALENDAR_FIXTURE_FILE)?)?;
    finance.validate()?;
    Ok(LifeFixtures {
        finance,
        email,
        calendar,
    })
}

/// Synthetic monthly budget with canaries in fields excluded from summaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FinanceFixture {
    /// The canonical summary month, `YYYY-MM`.
    pub month: String,
    pub categories: Vec<FinanceCategoryFixture>,
    /// Envelope budget allocations for the month, by category name.
    #[serde(default)]
    pub budgets: Vec<FinanceBudgetFixture>,
    /// Fabricated accounts. Fixture account names deliberately embed a
    /// fake account number canary.
    pub accounts: Vec<FinanceAccountFixture>,
    pub transactions: Vec<FinanceTransactionFixture>,
    /// Canary strings that must never appear in any outgoing envelope.
    #[serde(default)]
    pub planted_identifiers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FinanceCategoryFixture {
    pub name: String,
    #[serde(default)]
    pub is_income: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FinanceBudgetFixture {
    pub category: String,
    pub amount_cents: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FinanceAccountFixture {
    pub name: String,
    #[serde(default)]
    pub offbudget: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct FinanceTransactionFixture {
    /// Account name (must match a fixture account).
    pub account: String,
    /// Category name (must match a fixture category).
    pub category: String,
    /// `YYYY-MM-DD`.
    pub date: String,
    /// Minor units; negative for spending (Actual's sign convention).
    pub amount_cents: i64,
    /// Fabricated note text may embed a token canary.
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tombstone: bool,
}

impl FinanceFixture {
    fn validate(&self) -> Result<(), FixtureError> {
        parse_month_key(&self.month)?;
        for transaction in &self.transactions {
            parse_date_key(&transaction.date)?;
            if !self
                .accounts
                .iter()
                .any(|account| account.name == transaction.account)
            {
                return Err(FixtureError::Invalid(
                    "a fixture transaction references an unknown account".to_owned(),
                ));
            }
            if !self
                .categories
                .iter()
                .any(|category| category.name == transaction.category)
            {
                return Err(FixtureError::Invalid(
                    "a fixture transaction references an unknown category".to_owned(),
                ));
            }
            if transaction.category.is_empty() || transaction.account.is_empty() {
                return Err(FixtureError::Invalid(
                    "fixture account and category names must not be empty".to_owned(),
                ));
            }
        }
        for budget in &self.budgets {
            if !self
                .categories
                .iter()
                .any(|category| category.name == budget.category)
            {
                return Err(FixtureError::Invalid(
                    "a fixture budget references an unknown category".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// with exactly this fixture's synthetic rows. The file the finance
    /// adapter later opens is indistinguishable in shape from a production
    /// budget: same tables, same column names, same storage conventions.
    pub fn create_budget_db(&self, path: &Path) -> Result<(), FixtureError> {
        if path.exists() {
            return Err(FixtureError::Invalid(
                "the fixture budget database already exists".to_owned(),
            ));
        }
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                name TEXT,
                offbudget INTEGER DEFAULT 0,
                closed INTEGER DEFAULT 0,
                tombstone INTEGER DEFAULT 0
            );
            CREATE TABLE category_groups (
                id TEXT PRIMARY KEY,
                name TEXT,
                is_income INTEGER DEFAULT 0,
                sort_order REAL,
                tombstone INTEGER DEFAULT 0
            );
            CREATE TABLE categories (
                id TEXT PRIMARY KEY,
                name TEXT,
                is_income INTEGER DEFAULT 0,
                cat_group TEXT,
                sort_order REAL,
                tombstone INTEGER DEFAULT 0
            );
            CREATE TABLE category_mapping (
                id TEXT PRIMARY KEY,
                transferId TEXT
            );
            CREATE TABLE transactions (
                id TEXT PRIMARY KEY,
                isParent INTEGER DEFAULT 0,
                isChild INTEGER DEFAULT 0,
                parent_id TEXT,
                acct TEXT,
                category TEXT,
                amount INTEGER,
                description TEXT,
                notes TEXT,
                date INTEGER,
                transferred_id TEXT,
                sort_order REAL,
                cleared INTEGER DEFAULT 1,
                reconciled INTEGER DEFAULT 0,
                tombstone INTEGER DEFAULT 0
            );
            CREATE TABLE zero_budgets (
                id TEXT PRIMARY KEY,
                month INTEGER,
                category TEXT,
                amount INTEGER,
                carryover INTEGER DEFAULT 0,
                goal INTEGER,
                long_goal INTEGER
            );",
        )?;

        let month_key = parse_month_key(&self.month)?;
        for (index, account) in self.accounts.iter().enumerate() {
            connection.execute(
                "INSERT INTO accounts (id, name, offbudget) VALUES (?, ?, ?)",
                rusqlite::params![
                    format!("acct-{index}"),
                    account.name,
                    i64::from(account.offbudget),
                ],
            )?;
        }
        for (index, category) in self.categories.iter().enumerate() {
            let id = category_id(index);
            connection.execute(
                "INSERT INTO categories (id, name, is_income, cat_group) VALUES (?, ?, ?, ?)",
                rusqlite::params![id, category.name, i64::from(category.is_income), "grp-0"],
            )?;
            // Non-transfer categories map identity-to-identity, exactly as a
            // real budget's category_mapping does for plain categories.
            connection.execute(
                "INSERT INTO category_mapping (id, transferId) VALUES (?, ?)",
                rusqlite::params![id, id],
            )?;
        }
        connection.execute(
            "INSERT INTO category_groups (id, name, is_income) VALUES (?, ?, ?)",
            rusqlite::params!["grp-0", "Fixture Groups", 0],
        )?;
        for (index, transaction) in self.transactions.iter().enumerate() {
            let account_index = self
                .accounts
                .iter()
                .position(|account| account.name == transaction.account)
                .ok_or(FixtureError::Invalid(
                    "a fixture transaction references an unknown account".to_owned(),
                ))?;
            let category_index = self
                .categories
                .iter()
                .position(|category| category.name == transaction.category)
                .ok_or(FixtureError::Invalid(
                    "a fixture transaction references an unknown category".to_owned(),
                ))?;
            connection.execute(
                "INSERT INTO transactions
                    (id, acct, category, amount, description, notes, date, tombstone)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rusqlite::params![
                    format!("txn-{index}"),
                    format!("acct-{account_index}"),
                    category_id(category_index),
                    transaction.amount_cents,
                    format!("Fixture payee {index}"),
                    transaction.notes,
                    parse_date_key(&transaction.date)?,
                    i64::from(transaction.tombstone),
                ],
            )?;
        }
        for (index, budget) in self.budgets.iter().enumerate() {
            let category_index = self
                .categories
                .iter()
                .position(|category| category.name == budget.category)
                .ok_or(FixtureError::Invalid(
                    "a fixture budget references an unknown category".to_owned(),
                ))?;
            connection.execute(
                "INSERT INTO zero_budgets (id, month, category, amount) VALUES (?, ?, ?, ?)",
                rusqlite::params![
                    format!("budget-{index}"),
                    month_key,
                    category_id(category_index),
                    budget.amount_cents,
                ],
            )?;
        }
        Ok(())
    }
}

fn category_id(index: usize) -> String {
    format!("cat-{index}")
}

/// `YYYY-MM` -> integer `YYYYMM`, Actual's stored budget-month form.
fn parse_month_key(raw: &str) -> Result<i64, FixtureError> {
    let bytes = raw.as_bytes();
    if bytes.len() != 7
        || bytes[4] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..].iter().all(u8::is_ascii_digit)
    {
        return Err(FixtureError::Invalid(
            "fixture months must be YYYY-MM".to_owned(),
        ));
    }
    let year: i64 = raw[..4].parse().map_err(|error| {
        FixtureError::Invalid(format!("fixture year in {raw:?} is invalid: {error}"))
    })?;
    let month: i64 = raw[5..7].parse().map_err(|error| {
        FixtureError::Invalid(format!("fixture month in {raw:?} is invalid: {error}"))
    })?;
    if !(1970..=2099).contains(&year) || !(1..=12).contains(&month) {
        return Err(FixtureError::Invalid(
            "fixture month is out of range".to_owned(),
        ));
    }
    Ok(year * 100 + month)
}

/// `YYYY-MM-DD` -> integer `YYYYMMDD`, Actual's stored date form
/// (`toDateRepr`).
fn parse_date_parts(raw: &str) -> Result<(i64, i64, i64), FixtureError> {
    let bytes = raw.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..].iter().all(u8::is_ascii_digit)
    {
        return Err(FixtureError::Invalid(
            "fixture dates must be YYYY-MM-DD".to_owned(),
        ));
    }
    let year: i64 = raw[..4].parse().map_err(|error| {
        FixtureError::Invalid(format!("fixture year in {raw:?} is invalid: {error}"))
    })?;
    let month: i64 = raw[5..7].parse().map_err(|error| {
        FixtureError::Invalid(format!("fixture month in {raw:?} is invalid: {error}"))
    })?;
    let day: i64 = raw[8..10].parse().map_err(|error| {
        FixtureError::Invalid(format!("fixture day in {raw:?} is invalid: {error}"))
    })?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(FixtureError::Invalid(
            "fixture date is out of range".to_owned(),
        ));
    }
    Ok((year, month, day))
}

/// `YYYY-MM-DD` -> integer `YYYYMMDD`, Actual's stored date form
/// (`toDateRepr`).
fn parse_date_key(raw: &str) -> Result<i64, FixtureError> {
    let (year, month, day) = parse_date_parts(raw)?;
    Ok(year * 10_000 + month * 100 + day)
}

/// Synthetic email fixture: fabricated subscription receipts an ODIN-02
/// request can summarize and draft against. Addresses are `*.example`,
/// bodies are invented; no real communication is represented.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct EmailFixture {
    pub messages: Vec<EmailMessageFixture>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct EmailMessageFixture {
    pub id: String,
    pub from: String,
    pub subject: String,
    pub body: String,
    /// RFC 3339 timestamp.
    pub received_at: String,
    /// Optional cadence hint, e.g. `monthly`.
    #[serde(default)]
    pub subscription_hint: Option<String>,
}

/// Synthetic calendar fixture: fabricated events supporting the ODIN-02
/// Friday-reminder step (the fixture includes a dated Friday event).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CalendarFixture {
    pub events: Vec<CalendarEventFixture>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CalendarEventFixture {
    pub id: String,
    pub title: String,
    /// `YYYY-MM-DD`.
    pub date: String,
    /// Optional `HH:MM` local time.
    #[serde(default)]
    pub time: Option<String>,
    #[serde(default)]
    pub reminder: bool,
}
