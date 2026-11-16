//! Host-local usage readers. Credentials stay with their owning CLI/host; only readings cross SSH.
//! Provider amounts are authoritative; ccusage is a local list-price estimate, never an invoice.
use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Book, HOLD_AT, RETURN_AT};

const USAGE_COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const USAGE_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
const ACCOUNT_USAGE_TIMEOUT: Duration = Duration::from_secs(6);
/// Where each provider publishes an account's quota or balance; a source's `url` replaces it.
const ZAI_QUOTA: &str = "https://api.z.ai/api/monitor/usage/quota/limit";
const DEEPSEEK_BALANCE: &str = "https://api.deepseek.com/user/balance";
const OPENROUTER_CREDITS: &str = "https://openrouter.ai/api/v1/credits";

fn now_ms() -> i64 {
    i64::try_from(super::super::unix_ms(time::OffsetDateTime::now_utc())).unwrap_or(i64::MAX)
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Usage {
    pub account: String,
    pub provider: String,
    pub billing: String,
    pub source: String,
    pub host: Option<String>,
    pub source_account: Option<String>,
    pub label: String,
    pub span: Option<String>,
    pub unit: String,
    pub used: Option<f64>,
    pub limit: Option<f64>,
    pub remaining: Option<f64>,
    pub used_fraction: Option<f64>,
    pub resets_at: Option<i64>,
    pub fetched_at: Option<i64>,
    pub included: bool,
    pub estimate: bool,
    pub billed_usd: Option<f64>,
    pub estimated_usd: Option<f64>,
    pub tokens: Option<u64>,
    pub requests: Option<u64>,
    pub seat: Option<String>,
    pub workload: Option<String>,
    pub session: Option<String>,
    /// False for tool-only quotas and observational estimates.
    pub routing: bool,
}

impl Usage {
    fn new(account: String, provider: &str, billing: &str, source: &Source) -> Self {
        Self {
            account,
            provider: provider.to_owned(),
            billing: billing.to_owned(),
            source: source.kind.clone(),
            host: Some(source.host.clone()),
            source_account: source.source_account.clone(),
            label: String::new(),
            span: None,
            unit: "unknown".to_owned(),
            used: None,
            limit: None,
            remaining: None,
            used_fraction: None,
            resets_at: None,
            fetched_at: None,
            included: billing == "subscription",
            estimate: false,
            billed_usd: None,
            estimated_usd: None,
            tokens: None,
            requests: None,
            seat: None,
            workload: None,
            session: None,
            routing: true,
        }
    }

    pub(super) fn hold(&self, held: bool) -> Option<String> {
        if !self.routing || self.estimate {
            return None;
        }
        let threshold = if held { RETURN_AT } else { HOLD_AT };
        if self.used_fraction.is_some_and(|used| used >= threshold)
            || self.remaining.is_some_and(|remaining| remaining <= 0.0)
        {
            Some(format!(
                "{}: {} {} used of {} {} (reset {})",
                self.source,
                self.label,
                self.used
                    .map_or_else(|| "unknown".to_owned(), |n| n.to_string()),
                self.limit
                    .map_or_else(|| "unknown".to_owned(), |n| n.to_string()),
                self.unit,
                self.resets_at
                    .map_or_else(|| "not supplied".to_owned(), |n| n.to_string())
            ))
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct SourceError {
    pub account: Option<String>,
    pub source: String,
    pub host: Option<String>,
    pub message: String,
}

#[derive(Debug, Default)]
pub(super) struct Collected {
    pub usages: Vec<Usage>,
    pub errors: Vec<SourceError>,
}

#[derive(Debug, Deserialize)]
struct Config {
    sources: Vec<Source>,
}

#[derive(Debug, Deserialize)]
struct Binding {
    account: String,
    #[serde(default)]
    source_account: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Source {
    kind: String,
    host: String,
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    accounts: BTreeMap<String, Binding>,
    #[serde(default)]
    provider_billing: BTreeMap<String, String>,
    account: Option<String>,
    source_account: Option<String>,
    credential_env: Option<String>,
    credential_file: Option<String>,
    /// The account endpoint, when not the provider's published one.
    #[serde(default)]
    url: Option<String>,
}

impl Source {
    fn error(&self, account: Option<String>, message: impl Into<String>) -> SourceError {
        SourceError {
            account,
            source: self.kind.clone(),
            host: Some(self.host.clone()),
            message: message.into(),
        }
    }

    fn failed(&self, message: String, out: &mut Collected) {
        if self.accounts.is_empty() {
            out.errors.push(self.error(self.account.clone(), message));
        } else {
            for binding in self.accounts.values() {
                out.errors
                    .push(self.error(Some(binding.account.clone()), message.clone()));
            }
        }
    }
}

pub(super) fn collect(book: &Book) -> Collected {
    let mut out = Collected::default();
    let path = std::env::var_os("ODIN_MODEL_USAGE_CONFIG")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(|p| std::path::PathBuf::from(p).join("odin/model-usage.json"))
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|p| std::path::PathBuf::from(p).join(".config/odin/model-usage.json"))
        });
    let config = path
        .ok_or_else(|| "model usage configuration path is unavailable".to_owned())
        .and_then(|path| {
            std::fs::read(path).map_err(|e| format!("model usage configuration is unreadable: {e}"))
        })
        .and_then(|bytes| {
            serde_json::from_slice::<Config>(&bytes)
                .map_err(|e| format!("model usage configuration is invalid: {e}"))
        });
    let config = match config {
        Ok(config) => config,
        Err(message) => {
            out.errors.push(SourceError {
                account: None,
                source: "configuration".to_owned(),
                host: None,
                message,
            });
            return out;
        }
    };
    // Read independent hosts concurrently; one offline laptop must not stall every source in series.
    std::thread::scope(|scope| {
        let jobs: Vec<_> = config
            .sources
            .iter()
            .map(|source| {
                scope.spawn(move || {
                    let mut result = Collected::default();
                    let reading = match source.kind.as_str() {
                        "omp" => command_json(&source.command)
                            .and_then(|value| parse_omp(&value, source, book, &mut result)),
                        "ccusage" => command_json(&source.command)
                            .and_then(|value| parse_ccusage(&value, source, &mut result)),
                        "zai" => read_account(source, ZAI_QUOTA)
                            .and_then(|value| parse_zai(&value, source, &mut result)),
                        "deepseek" => read_account(source, DEEPSEEK_BALANCE)
                            .and_then(|value| parse_balance(&value, source, &mut result)),
                        "openrouter" => read_account(source, OPENROUTER_CREDITS)
                            .and_then(|value| parse_balance(&value, source, &mut result)),
                        _ => Err("unknown usage source kind".to_owned()),
                    };
                    if let Err(error) = reading {
                        source.failed(error, &mut result);
                    }
                    result
                })
            })
            .collect();
        for (source, job) in config.sources.iter().zip(jobs) {
            match job.join() {
                Ok(result) => {
                    out.usages.extend(result.usages);
                    out.errors.extend(result.errors);
                }
                Err(_) => source.failed("usage reader panicked".to_owned(), &mut out),
            }
        }
    });
    out
}

fn command_json(argv: &[String]) -> Result<Value, String> {
    let (program, args) = argv
        .split_first()
        .ok_or("usage command is not configured")?;
    let output = odin_process::run_bounded(
        Command::new(program).args(args),
        None,
        odin_process::ChildBounds {
            timeout: USAGE_COMMAND_TIMEOUT,
            max_stdout_bytes: USAGE_OUTPUT_LIMIT,
            max_stderr_bytes: 0,
        },
    )
    .map_err(|e| format!("usage command could not start: {e}"))?;
    let status = output.status.ok_or("usage command timed out")?;
    if !status.success() {
        return Err(format!("usage command exited {status}"));
    }
    if output.stdout.truncated() {
        return Err("usage output exceeds 8 MiB".to_owned());
    }
    serde_json::from_slice(output.stdout.as_bytes())
        .map_err(|e| format!("usage command returned invalid JSON: {e}"))
}

fn number(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}
fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}
fn span(id: &str) -> &str {
    match id {
        "weekly" | "7d" | "1w" => "week",
        "monthly" | "30d" => "month",
        "24h" | "1d" => "day",
        other => other,
    }
}
fn identity(report: &Value) -> Option<String> {
    report
        .pointer("/metadata/accountId")
        .or_else(|| report.get("accountId"))
        .or_else(|| report.pointer("/metadata/email"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            report.get("limits")?.as_array()?.iter().find_map(|limit| {
                limit
                    .pointer("/scope/accountId")?
                    .as_str()
                    .map(str::to_owned)
            })
        })
}

fn parse_omp(
    value: &Value,
    source: &Source,
    book: &Book,
    out: &mut Collected,
) -> Result<(), String> {
    let reports = value
        .get("reports")
        .and_then(Value::as_array)
        .ok_or("omp returned no reports array")?;
    for report in reports {
        let provider = report
            .get("provider")
            .and_then(Value::as_str)
            .ok_or("omp report lacks provider")?;
        let source_account = identity(report);
        let binding = source.accounts.get(provider).filter(|binding| {
            binding
                .source_account
                .as_ref()
                .is_none_or(|expected| Some(expected) == source_account.as_ref())
        });
        // A provider-only binding is safe only when this source returned exactly one account.
        let ambiguous = binding.is_some_and(|b| b.source_account.is_none())
            && reports
                .iter()
                .filter(|r| r["provider"].as_str() == Some(provider))
                .count()
                != 1;
        let account = if ambiguous {
            None
        } else {
            binding.map(|b| b.account.clone())
        };
        if ambiguous {
            out.errors.push(source.error(binding.map(|b| b.account.clone()), "multiple authenticated accounts: configure source_account before routing from this source"));
        }
        let account = account.unwrap_or_else(|| {
            format!(
                "{}:{provider}:{}",
                source.host,
                source_account.as_deref().unwrap_or("default")
            )
        });
        let billing = book
            .accounts
            .get(&account)
            .map(|a| a.billing.as_str())
            .or_else(|| source.provider_billing.get(provider).map(String::as_str))
            .unwrap_or("unknown");
        if report.get("error").is_some_and(|e| !e.is_null()) {
            out.errors
                .push(source.error(Some(account), "provider usage report is unreadable"));
            continue;
        }
        let Some(limits) = report
            .get("limits")
            .and_then(Value::as_array)
            .filter(|limits| !limits.is_empty())
        else {
            out.errors.push(source.error(
                Some(account),
                "provider supplied no usage limits or balance",
            ));
            continue;
        };
        for limit in limits {
            let mut row = Usage::new(account.clone(), provider, billing, source);
            row.source_account = source_account.clone();
            row.label = text(limit, "label")
                .or_else(|| text(limit, "id"))
                .unwrap_or_else(|| provider.to_owned());
            row.span = limit
                .pointer("/window/id")
                .and_then(Value::as_str)
                .map(|s| span(s).to_owned());
            row.resets_at = limit.pointer("/window/resetsAt").and_then(Value::as_i64);
            row.fetched_at = report.get("fetchedAt").and_then(Value::as_i64);
            let amount = &limit["amount"];
            row.unit = text(amount, "unit").unwrap_or_else(|| "unknown".to_owned());
            row.used = number(amount, "used");
            row.limit = number(amount, "limit");
            row.remaining = number(amount, "remaining");
            row.used_fraction = number(amount, "usedFraction")
                .or_else(|| number(amount, "remainingFraction").map(|n| 1.0 - n))
                .or_else(|| {
                    row.used
                        .zip(row.limit.filter(|n| *n > 0.0))
                        .map(|(used, limit)| used / limit)
                });
            if row.used.is_none() && row.remaining.is_none() && row.used_fraction.is_none() {
                out.errors.push(source.error(
                    Some(account.clone()),
                    format!("{} amount is unreadable", row.label),
                ));
                continue;
            }
            if limit
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|s| !matches!(s, "ok" | "warning" | "exhausted"))
            {
                out.errors.push(source.error(
                    Some(account.clone()),
                    format!("{} status is unreadable", row.label),
                ));
                continue;
            }
            out.usages.push(row);
        }
    }
    for key in ["accountsWithoutUsage", "disabledCredentials"] {
        for account in value
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let provider = account.get("provider").and_then(Value::as_str);
            let id = provider
                .and_then(|provider| source.accounts.get(provider))
                .map(|binding| binding.account.clone())
                .or_else(|| {
                    provider.map(|provider| {
                        format!(
                            "{}:{provider}:{}",
                            source.host,
                            identity(account).as_deref().unwrap_or("default")
                        )
                    })
                });
            out.errors
                .push(source.error(id, format!("OMP {key}: account reading unavailable")));
        }
    }
    for (provider, binding) in &source.accounts {
        if !out.usages.iter().any(|row| row.account == binding.account)
            && !out
                .errors
                .iter()
                .any(|error| error.account.as_ref() == Some(&binding.account))
        {
            out.errors.push(source.error(
                Some(binding.account.clone()),
                format!("no authenticated {provider} account reading"),
            ));
        }
    }
    Ok(())
}

fn parse_ccusage(value: &Value, source: &Source, out: &mut Collected) -> Result<(), String> {
    let sessions = value
        .get("sessions")
        .and_then(Value::as_array)
        .ok_or("ccusage returned no sessions array")?;
    let account = source
        .account
        .clone()
        .ok_or("ccusage account is not configured")?;
    if sessions.is_empty() {
        let mut row = Usage::new(account.clone(), "Claude Code", "subscription", source);
        row.label = "No Claude sessions in the local reporting window".to_owned();
        row.unit = "tokens".to_owned();
        row.estimate = true;
        row.routing = false;
        row.tokens = Some(0);
        row.used = Some(0.0);
        row.fetched_at = Some(now_ms());
        out.usages.push(row);
    }
    for session in sessions {
        let mut row = Usage::new(account.clone(), "Claude Code", "subscription", source);
        row.label = "Claude session (local log estimate)".to_owned();
        row.span = Some("session".to_owned());
        row.unit = "tokens".to_owned();
        row.estimate = true;
        row.routing = false;
        row.session = text(session, "sessionId");
        row.tokens = session.get("totalTokens").and_then(Value::as_u64);
        row.used = row.tokens.map(|n| n as f64);
        // ccusage emits zero for unknown model prices. Do not present that as a free session.
        let unknown_price = session
            .get("modelBreakdowns")
            .and_then(Value::as_array)
            .is_none_or(|models| {
                models.is_empty()
                    || models.iter().any(|model| {
                        number(model, "cost").is_none_or(|cost| cost == 0.0)
                            && [
                                "inputTokens",
                                "outputTokens",
                                "cacheCreationTokens",
                                "cacheReadTokens",
                            ]
                            .iter()
                            .any(|key| number(model, key).is_some_and(|n| n > 0.0))
                    })
            });
        row.estimated_usd = (!unknown_price)
            .then(|| number(session, "totalCost"))
            .flatten();
        row.fetched_at = Some(now_ms());
        if row.session.is_none() || row.tokens.is_none() {
            return Err("ccusage session is missing its identity or token count".to_owned());
        }
        if unknown_price {
            out.errors.push(source.error(
                Some(account.clone()),
                format!(
                    "session {} has unpriced models; dollar estimate unavailable",
                    row.session.as_deref().unwrap_or_default()
                ),
            ));
        }
        out.usages.push(row);
    }
    Ok(())
}

fn read_account(source: &Source, published: &str) -> Result<Value, String> {
    let endpoint = source.url.as_deref().unwrap_or(published);
    let env = source
        .credential_env
        .as_deref()
        .ok_or("account credential environment name is not configured")?;
    let key = std::env::var(env)
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let raw = std::fs::read_to_string(source.credential_file.as_ref()?).ok()?;
            raw.lines().find_map(|line| {
                line.strip_prefix(&format!("{env}="))
                    .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_owned())
            })
        })
        .filter(|s| !s.is_empty())
        .ok_or("account credential is unreadable on this host")?;
    let client =
        crate::http_pool::default_redirect().map_err(|_| "account HTTP client unavailable")?;
    let response = client
        .get(endpoint)
        .bearer_auth(key)
        .timeout(ACCOUNT_USAGE_TIMEOUT)
        .send()
        .map_err(|_| "account usage request failed")?;
    if !response.status().is_success() {
        return Err(format!("account usage HTTP {}", response.status()));
    }
    response
        .json()
        .map_err(|_| "account usage response is not JSON".to_owned())
}

fn parse_zai(value: &Value, source: &Source, out: &mut Collected) -> Result<(), String> {
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        return Err("Z.ai rejected the account usage request".to_owned());
    }
    let limits = value
        .pointer("/data/limits")
        .and_then(Value::as_array)
        .filter(|limits| !limits.is_empty())
        .ok_or("Z.ai supplied no quota limits")?;
    let account = source
        .account
        .clone()
        .ok_or("Z.ai account is not configured")?;
    for limit in limits {
        let mut row = Usage::new(account.clone(), "Z.ai Coding Plan", "subscription", source);
        let kind = limit
            .get("rawType")
            .or_else(|| limit.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        row.routing = kind == "TOKENS_LIMIT";
        row.span = match limit.get("unit").and_then(Value::as_u64) {
            Some(3) => Some("5h"),
            Some(6) => Some("week"),
            Some(5) => Some("month"),
            _ => None,
        }
        .map(str::to_owned);
        row.label = format!(
            "{} {}",
            kind,
            row.span.as_deref().unwrap_or("unknown window")
        );
        row.unit = if row.routing { "tokens" } else { "requests" }.to_owned();
        row.used = number(limit, "currentValue");
        row.limit = number(limit, "usage");
        row.remaining = number(limit, "remaining");
        row.used_fraction = number(limit, "percentage").map(|n| n / 100.0).or_else(|| {
            row.used
                .zip(row.limit.filter(|n| *n > 0.0))
                .map(|(used, limit)| used / limit)
        });
        row.resets_at = limit.get("nextResetTime").and_then(Value::as_i64);
        row.fetched_at = Some(now_ms());
        if row.used_fraction.is_none() && row.used.is_none() && row.remaining.is_none() {
            return Err("Z.ai quota amount is unreadable".to_owned());
        }
        out.usages.push(row);
    }
    Ok(())
}

fn parse_balance(value: &Value, source: &Source, out: &mut Collected) -> Result<(), String> {
    let account = source
        .account
        .clone()
        .ok_or("balance account is not configured")?;
    let mut row = Usage::new(account, &source.kind, "api", source);
    row.label = "Credit balance".to_owned();
    row.fetched_at = Some(now_ms());
    if source.kind == "deepseek" {
        if value.get("is_available").and_then(Value::as_bool) == Some(false) {
            return Err("DeepSeek account balance is unavailable".to_owned());
        }
        let balances = value
            .get("balance_infos")
            .and_then(Value::as_array)
            .ok_or("DeepSeek supplied no balances")?;
        let available = balances.iter().any(|balance| {
            balance
                .get("total_balance")
                .and_then(|n| n.as_f64().or_else(|| n.as_str()?.parse().ok()))
                .is_some_and(|n| n > 0.0)
        });
        for balance in balances {
            let mut balance_row = row.clone();
            balance_row.routing = !available;
            balance_row.unit =
                text(balance, "currency").ok_or("DeepSeek balance has no currency")?;
            balance_row.remaining = balance
                .get("total_balance")
                .and_then(|n| n.as_f64().or_else(|| n.as_str()?.parse().ok()));
            if balance_row.remaining.is_none() {
                return Err("DeepSeek balance is unreadable".to_owned());
            }
            out.usages.push(balance_row);
        }
        if balances.is_empty() {
            return Err("DeepSeek supplied no balances".to_owned());
        }
    } else {
        row.unit = "USD".to_owned();
        row.limit = value.pointer("/data/total_credits").and_then(Value::as_f64);
        row.used = value.pointer("/data/total_usage").and_then(Value::as_f64);
        row.remaining = row.limit.zip(row.used).map(|(limit, used)| limit - used);
        if row.remaining.is_none() {
            return Err("OpenRouter credit balance is unreadable".to_owned());
        }
        // A prepaid lifetime balance is not a rolling window: move off only when exhausted.
        out.usages.push(row);
    }
    Ok(())
}

pub(super) fn gateway_usages(book: &Book, summary: &Value) -> Vec<Usage> {
    let source = Source {
        kind: "gateway".to_owned(),
        host: "gateway".to_owned(),
        command: Vec::new(),
        accounts: BTreeMap::new(),
        account: None,
        source_account: None,
        credential_env: None,
        credential_file: None,
        url: None,
        provider_billing: BTreeMap::new(),
    };
    book.accounts
        .values()
        .filter_map(|account| {
            let groups = book.groups_of(&account.id);
            let rows: Vec<_> = summary
                .get("lanes")?
                .as_array()?
                .iter()
                .filter(|row| {
                    row["lane"]
                        .as_str()
                        .is_some_and(|lane| groups.iter().any(|group| group == lane))
                })
                .collect();
            if rows.is_empty() {
                return None;
            }
            let mut row = Usage::new(
                account.id.clone(),
                &account.provider,
                &account.billing,
                &source,
            );
            row.host = None;
            row.label = "Gateway seven-day list-price estimate".to_owned();
            row.span = Some("week".to_owned());
            row.unit = "USD".to_owned();
            row.estimate = true;
            row.routing = false;
            row.billed_usd = Some(rows.iter().filter_map(|r| number(r, "usd")).sum());
            row.estimated_usd = Some(rows.iter().filter_map(|r| number(r, "included_usd")).sum());
            row.used =
                Some(row.billed_usd.unwrap_or_default() + row.estimated_usd.unwrap_or_default());
            row.tokens = Some(rows.iter().filter_map(|r| r["tokens"].as_u64()).sum());
            row.requests = Some(rows.iter().filter_map(|r| r["requests"].as_u64()).sum());
            row.fetched_at = Some(now_ms());
            Some(row)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn source(kind: &str) -> Source {
        serde_json::from_value(json!({"kind":kind,"host":"mini","account":"plan","source_account":"local-log-root","accounts":{}})).unwrap()
    }
    #[test]
    fn provider_limits_balances_and_identity_survive_normalization() {
        let mut source = source("omp");
        source.accounts.insert(
            "commandcode".to_owned(),
            Binding {
                account: "plan".to_owned(),
                source_account: Some("provider-account".to_owned()),
            },
        );
        let mut out = Collected::default();
        parse_omp(&json!({"reports":[{"provider":"commandcode","fetchedAt":1000,"metadata":{"accountId":"provider-account"},"limits":[
            {"label":"5h","window":{"id":"5h","resetsAt":9000},"amount":{"unit":"credits","used":13,"limit":14,"usedFraction":0.93},"status":"ok"},
            {"label":"Balance","amount":{"unit":"credits","remaining":70}}
        ]}]}), &source, &Book::default(), &mut out).unwrap();
        assert_eq!(out.usages[0].account, "plan");
        assert_eq!(
            out.usages[0].source_account.as_deref(),
            Some("provider-account")
        );
        assert_eq!(out.usages[0].resets_at, Some(9000));
        assert!(out.usages[0].hold(false).is_some());
        assert_eq!(out.usages[1].remaining, Some(70.0));
        assert_eq!(out.usages[1].used, None);
    }

    #[test]
    fn multiple_provider_accounts_are_never_silently_combined_for_routing() {
        let mut source = source("omp");
        source.accounts.insert(
            "p".to_owned(),
            Binding {
                account: "plan".to_owned(),
                source_account: None,
            },
        );
        let mut out = Collected::default();
        parse_omp(&json!({"reports":[
            {"provider":"p","metadata":{"accountId":"one"},"limits":[{"amount":{"unit":"percent","used":1,"limit":100}}]},
            {"provider":"p","metadata":{"accountId":"two"},"limits":[{"amount":{"unit":"percent","used":2,"limit":100}}]}
        ]}), &source, &Book::default(), &mut out).unwrap();
        assert!(out.usages.iter().all(|row| row.account != "plan"));
        assert_eq!(out.usages[0].source_account.as_deref(), Some("one"));
        assert_eq!(out.usages[1].source_account.as_deref(), Some("two"));
        assert!(out
            .errors
            .iter()
            .all(|error| error.account.as_deref() == Some("plan")));
    }

    /// A loopback account endpoint answering `status` with `body`, and the request it saw.
    fn account_endpoint(status: &str, body: &str) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/usage", listener.local_addr().unwrap());
        let (seen, request) = std::sync::mpsc::channel();
        let reply = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = String::new();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                head.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            stream.write_all(reply.as_bytes()).unwrap();
            seen.send(head).unwrap();
        });
        (url, request)
    }

    fn account_source(url: &str, env: &str) -> Source {
        serde_json::from_value(json!({"kind":"deepseek","host":"mini","account":"plan",
            "credential_env": env, "url": url}))
        .unwrap()
    }

    /// An account endpoint is asked with the bearer key from the named environment variable;
    /// an error status and a non-JSON answer each name their cause.
    #[test]
    fn an_account_reading_sends_its_key_and_names_what_went_wrong() {
        let key = "ODIN_TEST_USAGE_KEY_OK";
        std::env::set_var(key, "secret-key");
        let (url, request) = account_endpoint("200 OK", r#"{"balance_infos":[]}"#);
        let value = read_account(&account_source(&url, key), DEEPSEEK_BALANCE).unwrap();
        assert_eq!(value, json!({"balance_infos":[]}));
        assert!(request
            .recv()
            .unwrap()
            .to_ascii_lowercase()
            .contains("authorization: bearer secret-key"));
        let (url, _) = account_endpoint("503 Service Unavailable", "{}");
        let error = read_account(&account_source(&url, key), DEEPSEEK_BALANCE).unwrap_err();
        assert!(error.contains("503"), "{error}");
        let (url, _) = account_endpoint("200 OK", "not json");
        let error = read_account(&account_source(&url, key), DEEPSEEK_BALANCE).unwrap_err();
        assert!(error.contains("not JSON"), "{error}");
        let error = read_account(
            &account_source(&url, "ODIN_TEST_USAGE_KEY_ABSENT"),
            DEEPSEEK_BALANCE,
        )
        .unwrap_err();
        assert!(error.contains("credential"), "{error}");
    }
}
