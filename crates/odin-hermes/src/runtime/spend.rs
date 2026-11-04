//! Read-only daily and per-lane cost, token and request totals from LiteLLM aggregates.
//! This surface does not enforce spending caps.
//!
//! Source: the host's LiteLLM gateway (`127.0.0.1:4000`, the fleet-wide
//! loopback), authenticated with the `LITELLM_MASTER_KEY` the daemon's
//! environment holds (never logged or returned). `/model/info` maps each
//! upstream model to the lane(s) that serve it; `/user/daily/activity`
//! carries the per-day, per-model metrics; `/tag/daily/activity` the
//! per-seat ones: every seat session's requests carry the tag
//! `seat:<seat>` (odin-omp stages `ODIN_SPEND_TAG`, the stock models.yml
//! sends it as `x-litellm-tags`), and the owner's own OMP sessions use the declared
//! `ODIN_SPEND_TAG`. Without that declaration, no unprefixed tag is treated as the owner.
//! LiteLLM has no tag-by-lane view, so a tag's subscription share is one read of that tag; the
//! share is kept with the tag's counts and read again only once they move (see `tag_view`).
//! An idle pass is three gateway requests (`/model/info`, `/user/daily/activity`,
//! `/tag/daily/activity`) while each activity view fits one 500-row page (rows are per day, tag
//! and model); a pass adds one read per tag whose counts moved, and a page per further 500 rows.
//! Each lane's billing comes from the declared book (`/model/info`, see `models`): dollars
//! on subscription lanes are what that use would cost at list price, reported apart as
//! `included_usd` because the plan already pays for it.

use super::tools::NO_GATEWAY;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::gateway;
use super::models::Book;
use super::tools::CapabilityTool;
use super::HermesRuntime;

const TOOL: &str = "spend_read";
const DEFAULT_DAYS: i64 = 7;
const MAX_DAYS: i64 = 31;
/// How long one gateway read may take.
pub(super) const GATEWAY_TIMEOUT: Duration = Duration::from_secs(30);
const SERVED_MODELS_TIMEOUT: Duration = Duration::from_secs(10);
const BOOK_SPEND_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Default)]
struct Tally {
    usd: f64,
    included: f64,
    tokens: u64,
    requests: u64,
}

impl Tally {
    /// `included` is the part of the metrics' spend a subscription already pays for.
    fn add(&mut self, metrics: &Value, included: f64) {
        let spend = metrics.get("spend").and_then(Value::as_f64).unwrap_or(0.0);
        self.usd += spend - included;
        self.included += included;
        self.tokens += metrics
            .get("total_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        self.requests += metrics
            .get("api_requests")
            .and_then(Value::as_u64)
            .unwrap_or(0);
    }

    fn json(&self) -> Value {
        let cents = |usd: f64| (usd.max(0.0) * 100.0).round() / 100.0;
        json!({
            "usd": cents(self.usd),
            "included_usd": cents(self.included),
            "tokens": self.tokens,
            "requests": self.requests,
        })
    }
}

/// The spend of one activity row's model groups that a subscription pays for.
fn included_spend(row: &Value, book: &Book) -> f64 {
    row.pointer("/breakdown/model_groups")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(group, _)| book.billing(group) == Some("subscription"))
        .filter_map(|(_, entry)| entry.pointer("/metrics/spend").and_then(Value::as_f64))
        .sum()
}

/// The owner-facing summary of `/user/daily/activity` results: per day,
/// per lane (busiest first), and in total.
pub(crate) fn summarize(activity: &Value, book: &Book, from: &str, to: &str) -> Value {
    let mut total = Tally::default();
    let mut per_lane: BTreeMap<String, Tally> = BTreeMap::new();
    let mut days = Vec::new();
    for day in activity
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let mut tally = Tally::default();
        if let Some(metrics) = day.get("metrics") {
            let included = included_spend(day, book);
            tally.add(metrics, included);
            total.add(metrics, included);
        }
        for (group, entry) in day
            .pointer("/breakdown/model_groups")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if let Some(metrics) = entry.get("metrics") {
                let included = if book.billing(group) == Some("subscription") {
                    metrics.get("spend").and_then(Value::as_f64).unwrap_or(0.0)
                } else {
                    0.0
                };
                per_lane
                    .entry(group.clone())
                    .or_default()
                    .add(metrics, included);
            }
        }
        let mut row = tally.json();
        row["date"] = day.get("date").cloned().unwrap_or(Value::Null);
        days.push(row);
    }
    days.sort_by(|a, b| a["date"].as_str().cmp(&b["date"].as_str()));
    let lanes = ranked(per_lane, "lane");
    let listed = lanes
        .iter()
        .filter_map(|lane| lane["lane"].as_str())
        .collect::<Vec<_>>()
        .join(", ");
    json!({
        "from": from,
        "to": to,
        "total": total.json(),
        "days": days,
        "lanes": lanes,
        "note": format!(
            "usd is money billed (API lanes); included_usd is subscription use at the lanes' list \
             prices, already paid by the plan. Lanes in this window: {}.",
            if listed.is_empty() { "none" } else { &listed }
        ),
    })
}

/// The owner-facing spender tag; workload and session dimensions are shown separately.
fn spender(tag: &str) -> Option<String> {
    if let Some(seat) = tag.strip_prefix("seat:") {
        return (!seat.is_empty()).then(|| seat.to_owned());
    }
    let owner = std::env::var("ODIN_SPEND_TAG").ok()?;
    (tag == owner).then(|| format!("{owner} (own sessions)"))
}

/// All attribution tags with spend in a `/tag/daily/activity` answer.
fn spending_tags(tag_activity: &Value) -> std::collections::BTreeSet<String> {
    tag_activity
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|day| {
            day.pointer("/breakdown/entities")
                .and_then(Value::as_object)
        })
        .flat_map(|entities| entities.keys())
        .filter(|tag| {
            spender(tag).is_some() || tag.starts_with("workload:") || tag.starts_with("session:")
        })
        .cloned()
        .collect()
}

/// Busiest first, each row labelled under `key`.
fn ranked(tallies: BTreeMap<String, Tally>, key: &str) -> Vec<Value> {
    let mut rows: Vec<(String, Tally)> = tallies.into_iter().collect();
    rows.sort_by(|(_, a), (_, b)| {
        (b.usd + b.included)
            .partial_cmp(&(a.usd + a.included))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.tokens.cmp(&a.tokens))
    });
    rows.into_iter()
        .map(|(label, tally)| {
            let mut row = tally.json();
            row[key] = json!(label);
            row
        })
        .collect()
}

/// Per-seat and per-pod-workload totals from `/tag/daily/activity`
/// (busiest first), plus the remainder of `total_usd` (billed dollars) no seat tag accounts
/// for (embeddings, requests from before tagging, tools that call the
/// gateway directly). A pod session's requests carry its seat and
/// `workload:<profile>`, so the workloads answer "what did this pod cost"
/// within their seats' totals. `included` is each tag's subscription share.
pub(crate) fn summarize_tags(
    tag_activity: &Value,
    total_usd: f64,
    included: &BTreeMap<String, f64>,
) -> Value {
    let mut per_seat: BTreeMap<String, Tally> = BTreeMap::new();
    let mut per_workload: BTreeMap<String, Tally> = BTreeMap::new();
    let mut per_session: BTreeMap<String, Tally> = BTreeMap::new();
    for day in tag_activity
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for (tag, entry) in day
            .pointer("/breakdown/entities")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let Some(metrics) = entry.get("metrics") else {
                continue;
            };
            if let Some(seat) = spender(tag) {
                per_seat.entry(seat).or_default().add(metrics, 0.0);
            } else if let Some(profile) = tag.strip_prefix("workload:").filter(|p| !p.is_empty()) {
                per_workload
                    .entry(profile.to_owned())
                    .or_default()
                    .add(metrics, 0.0);
            } else if let Some(session) = tag.strip_prefix("session:").filter(|s| !s.is_empty()) {
                per_session
                    .entry(session.to_owned())
                    .or_default()
                    .add(metrics, 0.0);
            }
        }
    }
    for (tag, share) in included {
        let tally = match spender(tag) {
            Some(seat) => per_seat.get_mut(&seat),
            None => tag
                .strip_prefix("workload:")
                .and_then(|profile| per_workload.get_mut(profile))
                .or_else(|| {
                    tag.strip_prefix("session:")
                        .and_then(|session| per_session.get_mut(session))
                }),
        };
        if let Some(tally) = tally {
            tally.usd -= share;
            tally.included += share;
        }
    }
    let attributed: f64 = per_seat.values().map(|tally| tally.usd).sum();
    json!({
        "seats": ranked(per_seat, "seat"),
        "workloads": ranked(per_workload, "workload"),
        "sessions": ranked(per_session, "session"),
        "untagged_usd": (((total_usd - attributed).max(0.0)) * 100.0).round() / 100.0,
    })
}

pub(super) fn fetch(
    client: &reqwest::blocking::Client,
    gateway: &str,
    key: &str,
    path: &str,
    timeout: Duration,
) -> Result<Value, String> {
    let response = client
        .get(format!("{gateway}{path}"))
        .timeout(timeout)
        .bearer_auth(key)
        .send()
        .map_err(|error| format!("gateway {path} unreachable: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("gateway {path} answered {status}"));
    }
    response
        .json::<Value>()
        .map_err(|error| format!("gateway {path} answered unreadable JSON: {error}"))
}

/// Daily activity is paginated over (day, entity, model) rows; every request asks for this page size.
const ACTIVITY_PAGE_SIZE: u32 = 500;
/// A bound on the pages one view reads.
const ACTIVITY_MAX_PAGES: u32 = 40;

/// Every page of one daily-activity view, merged into one `results` array.
pub(super) fn fetch_all_pages(
    client: &reqwest::blocking::Client,
    gateway: &str,
    key: &str,
    path: &str,
    timeout: Duration,
) -> Result<Value, String> {
    let mut pages = Vec::new();
    let deadline = Instant::now() + timeout;
    for page in 1..=ACTIVITY_MAX_PAGES {
        let value = fetch(
            client,
            gateway,
            key,
            &format!("{path}&page_size={ACTIVITY_PAGE_SIZE}&page={page}"),
            deadline
                .checked_duration_since(Instant::now())
                .ok_or("gateway activity deadline elapsed")?,
        )?;
        if value.get("results").and_then(Value::as_array).is_none() {
            return Err(format!("gateway {path} returned no activity rows"));
        }
        let more = value
            .pointer("/metadata/has_more")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        pages.push(value);
        if !more {
            return Ok(merge_activity_pages(pages));
        }
    }
    tracing::warn!(
        "odin-hermes: spend view {path} has more than {ACTIVITY_MAX_PAGES} pages; read the first"
    );
    Ok(merge_activity_pages(pages))
}

/// One view from its pages: every page's `results`, in order.
fn merge_activity_pages(pages: Vec<Value>) -> Value {
    let results: Vec<Value> = pages
        .iter()
        .flat_map(|page| {
            page.get("results")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    json!({ "results": results })
}

/// The same summary for Huginn (`odin huginn spend`): what the host's
/// gateway spent over the last `days` days.
pub fn read_gateway_spend(gateway: &str, days: i64) -> Result<Value, String> {
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(format!("days must be 1..={MAX_DAYS}"));
    }
    read(gateway, days).map_err(|error| error.to_string())
}

/// Requests per gateway model group (lane) that answered one tag's
/// traffic, summed over the days of a `/tag/daily/activity?tags=<tag>`
/// answer (`breakdown.model_groups`, LiteLLM 1.97).
pub(crate) fn served_model_groups(tag_activity: &Value) -> BTreeMap<String, u64> {
    let mut served: BTreeMap<String, u64> = BTreeMap::new();
    for day in tag_activity
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for (group, entry) in day
            .pointer("/breakdown/model_groups")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let requests = entry
                .pointer("/metrics/api_requests")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            *served.entry(group.clone()).or_default() += requests;
        }
    }
    served
}

/// The `tags=<tag>` query parameter, encoded.
fn tag_query(tag: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("tags", tag)
        .finish()
}

/// The daily activity of one tag from the day before `since_ms` through tomorrow
/// (the padding absorbs the gateway's UTC day edges).
pub(super) fn tag_activity(
    gateway: &str,
    key: &str,
    tag: &str,
    since_ms: u64,
    timeout: Duration,
) -> Result<Value, String> {
    let since = i64::try_from(since_ms / 1000).unwrap_or(i64::MAX);
    let from = time::OffsetDateTime::from_unix_timestamp(since)
        .map_err(|error| format!("since {since_ms} is not a time: {error}"))?
        .date()
        - time::Duration::days(1);
    let to = time::OffsetDateTime::now_utc().date() + time::Duration::days(1);
    let client =
        crate::http_pool::default_redirect().map_err(|error| format!("gateway client: {error}"))?;
    fetch_all_pages(
        client,
        gateway,
        key,
        &format!(
            "/tag/daily/activity?{}&start_date={from}&end_date={to}",
            tag_query(tag)
        ),
        timeout,
    )
}

/// Reports model groups that served tagged requests since `since_ms`, including fallback lanes.
pub fn read_tag_model_groups(
    gateway: &str,
    tag: &str,
    since_ms: u64,
) -> Result<BTreeMap<String, u64>, String> {
    let key = gateway::key()?;
    tag_activity(gateway, &key, tag, since_ms, SERVED_MODELS_TIMEOUT)
        .map(|activity| served_model_groups(&activity))
}

fn read(gateway: &str, days: i64) -> Result<Value, HostToolError> {
    let key = gateway::key().map_err(|reason| HostToolError::unavailable(TOOL, reason))?;
    let client = crate::http_pool::default_redirect()
        .map_err(|error| HostToolError::unavailable(TOOL, format!("gateway client: {error}")))?;
    let model_info = fetch(client, gateway, &key, "/model/info", GATEWAY_TIMEOUT)
        .map_err(|error| HostToolError::unavailable(TOOL, error))?;
    let book = Book::from_model_info(&model_info)
        .map_err(|error| HostToolError::unavailable(TOOL, error))?;
    read_with_book(
        client,
        gateway,
        &key,
        &book,
        days,
        Instant::now() + GATEWAY_TIMEOUT,
    )
}

/// The usage board reuses its already-read book; spend.read remains the same standalone view.
pub(super) fn read_book_spend(gateway: &str, key: &str, book: &Book) -> Result<Value, String> {
    let client =
        crate::http_pool::default_redirect().map_err(|error| format!("gateway client: {error}"))?;
    read_with_book(
        client,
        gateway,
        key,
        book,
        DEFAULT_DAYS,
        Instant::now() + BOOK_SPEND_TIMEOUT,
    )
    .map_err(|error| error.to_string())
}

/// A tag's request and token counts over the window.
type Counts = (u64, u64);

/// Each tag's subscription share, by window and tag, with the counts it was read at. Bounded: a full
/// map is dropped and refilled, which costs one cold pass.
static SHARES: parking_lot::Mutex<BTreeMap<(String, String), (Counts, f64)>> =
    parking_lot::Mutex::new(BTreeMap::new());
const SHARES_MAX: usize = 4096;

/// A tag's request and token counts over the window, from its `entities` rows.
fn tag_counts(tag_activity: &Value, tag: &str) -> Counts {
    let mut counts = (0, 0);
    for metrics in tag_activity
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|day| {
            day.get("breakdown")?
                .get("entities")?
                .get(tag)?
                .get("metrics")
        })
    {
        counts.0 += metrics
            .get("api_requests")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        counts.1 += metrics
            .get("total_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
    }
    counts
}

/// One tag's subscription share of the window: its own per-lane read, with the counts it was read at.
fn tag_share(
    client: &reqwest::blocking::Client,
    gateway: &str,
    key: &str,
    book: &Book,
    range: &str,
    tag: &str,
    timeout: Duration,
) -> Result<(Counts, f64), String> {
    let own = fetch_all_pages(
        client,
        gateway,
        key,
        &format!("/tag/daily/activity?{}&{range}", tag_query(tag)),
        timeout,
    )?;
    let share = own
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|day| included_spend(day, book))
        .sum::<f64>();
    Ok((tag_counts(&own, tag), share))
}

/// The per-seat, per-workload and per-session view of one window: every tag's totals from the one
/// ranged `/tag/daily/activity` read, which groups by tag but not by lane. A tag's subscription share
/// needs its own per-lane breakdown, so it is one read of that tag, kept with the tag's counts and read
/// again only once they move: a pass reads just the tags that did work. (A declared billing change
/// shows from a tag's next request or the next day.) A tag whose read fails, or that the pass deadline
/// leaves unread, keeps its last share (none if never read) and the view still lands; the view's
/// `share_error` says how many and why.
fn tag_view(
    client: &reqwest::blocking::Client,
    gateway: &str,
    key: &str,
    book: &Book,
    range: &str,
    billed_usd: f64,
    deadline: Instant,
) -> Result<Value, String> {
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .ok_or("gateway attribution deadline elapsed")
    };
    let tags = fetch_all_pages(
        client,
        gateway,
        key,
        &format!("/tag/daily/activity?{range}"),
        remaining()?,
    )?;
    let mut included = BTreeMap::new();
    let mut unread = 0_u32;
    let mut first_error: Option<String> = None;
    for tag in spending_tags(&tags) {
        let counts = tag_counts(&tags, &tag);
        let cached = SHARES.lock().get(&(range.to_owned(), tag.clone())).copied();
        let share = match cached {
            Some((read_at, share)) if read_at == counts => share,
            _ => match remaining()
                .map_err(str::to_owned)
                .and_then(|timeout| tag_share(client, gateway, key, book, range, &tag, timeout))
            {
                Ok((read_at, share)) => {
                    let mut shares = SHARES.lock();
                    if shares.len() >= SHARES_MAX {
                        shares.clear();
                    }
                    shares.insert((range.to_owned(), tag.clone()), (read_at, share));
                    share
                }
                Err(error) => {
                    unread += 1;
                    first_error.get_or_insert(error);
                    cached.map_or(0.0, |(_, share)| share)
                }
            },
        };
        included.insert(tag, share);
    }
    let mut view = summarize_tags(&tags, billed_usd, &included);
    if let Some(error) = first_error {
        view["share_error"] = json!(format!(
            "Subscription shares of {unread} tag(s) are unread (first cause: {error}); \
             their subscription use counts as billed until a later pass reads them."
        ));
    }
    Ok(view)
}

fn read_with_book(
    client: &reqwest::blocking::Client,
    gateway: &str,
    key: &str,
    book: &Book,
    days: i64,
    deadline: Instant,
) -> Result<Value, HostToolError> {
    let today = time::OffsetDateTime::now_utc().date();
    let from = today - time::Duration::days(days - 1);
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| HostToolError::unavailable(TOOL, "gateway attribution deadline elapsed"))
    };
    let activity = fetch_all_pages(
        client,
        gateway,
        key,
        &format!("/user/daily/activity?start_date={from}&end_date={today}"),
        remaining()?,
    )
    .map_err(|error| HostToolError::unavailable(TOOL, error))?;
    let mut summary = summarize(&activity, book, &from.to_string(), &today.to_string());
    let billed_usd = summary["total"]["usd"].as_f64().unwrap_or(0.0);
    // Per-seat attribution is additive: an unreadable tag view leaves the
    // per-day/per-lane answer intact and says why the seats are missing.
    let tags = tag_view(
        client,
        gateway,
        key,
        book,
        &format!("start_date={from}&end_date={today}"),
        billed_usd,
        deadline,
    );
    match tags {
        Ok(tags) => {
            summary["seats"] = tags["seats"].clone();
            summary["workloads"] = tags["workloads"].clone();
            summary["untagged_usd"] = tags["untagged_usd"].clone();
            summary["sessions"] = tags["sessions"].clone();
            if let Some(error) = tags["share_error"].as_str() {
                tracing::warn!(error = %error, "odin-hermes: spend read per-seat shares incomplete");
                summary["note"] = json!(format!(
                    "{} {error}",
                    summary["note"].as_str().unwrap_or_default()
                ));
            }
        }
        Err(error) => {
            tracing::warn!(error = %error, "odin-hermes: spend read per-seat view unavailable");
            summary["attribution_error"] = json!(error);
            summary["note"] = json!(format!(
                "{} Per-seat view unavailable: {error}.",
                summary["note"].as_str().unwrap_or_default()
            ));
        }
    }
    tracing::debug!(
        days,
        "odin-hermes: spend read days={days} usd={} requests={}",
        summary["total"]["usd"],
        summary["total"]["requests"]
    );
    Ok(summary)
}

pub(super) fn spend_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    let handler = move |_scope: Scope, arguments: Value| {
        let days = match arguments.get("days") {
            None | Some(Value::Null) => DEFAULT_DAYS,
            Some(value) => value
                .as_i64()
                .filter(|days| (1..=MAX_DAYS).contains(days))
                .ok_or_else(|| HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!("days must be an integer from 1 to {MAX_DAYS}"),
                })?,
        };
        let gateway = runtime
            .model_gateway()
            .ok_or_else(|| HostToolError::unavailable(TOOL, NO_GATEWAY))?;
        read(&gateway, days)
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Read model spend".into(),
            description:
                "What the model gateway spent over the last `days` days (default 7, \
                 at most 31): dollars billed (API lanes) and, apart, subscription use at list \
                 price (included in the plan), tokens and requests, per \
                 day, per lane, per seat and per pod workload, with the total. Use it for 'what did this week cost?'."
                    .into(),
            parameters: capability_parameters!("spend.read"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}

#[cfg(test)]
mod tests {

    use super::*;

    /// LiteLLM 1.97 `/model/info` (with the generated `model_info.odin`) and `/user/daily/activity`.
    #[test]
    fn a_week_of_gateway_activity_splits_billed_from_included() {
        let account = |id: &str, billing: &str| {
            json!({"id": id, "provider": id, "billing": billing, "monthly_usd": null, "renews": null,
                   "secret": null, "keyed": true, "windows": []})
        };
        let lane = |name: &str, account: Value| {
            json!({"model_name": name, "model_info": {"odin": {"account": account, "vision": false,
                   "context_window": 1000}}})
        };
        let model_info = json!({"data": [
            lane("grok", account("supergrok", "subscription")),
            lane("deepseek-chat", account("deepseek", "api")),
            lane("wemm-embedding", account("local", "local")),
        ]});
        let book = Book::from_model_info(&model_info).unwrap();
        let activity = json!({"results": [
            {"date": "2026-10-03", "metrics": {"spend": 29.6947, "total_tokens": 21598338u64, "api_requests": 109525u64},
             "breakdown": {"model_groups": {
                "grok": {"metrics": {"spend": 26.958, "total_tokens": 9000000u64, "api_requests": 300u64}},
                "deepseek-chat": {"metrics": {"spend": 2.7367, "total_tokens": 1200000u64, "api_requests": 90u64}},
                "wemm-embedding": {"metrics": {"spend": 0.0, "total_tokens": 9057271u64, "api_requests": 109000u64}}
             }}},
            {"date": "2026-10-02", "metrics": {"spend": 0.00043, "total_tokens": 100u64, "api_requests": 1u64},
             "breakdown": {"model_groups": {
                "deepseek-chat": {"metrics": {"spend": 0.00043, "total_tokens": 100u64, "api_requests": 1u64}}
             }}}
        ]});
        let summary = summarize(&activity, &book, "2026-09-27", "2026-10-03");
        assert_eq!(
            summary["total"]["usd"],
            json!(2.74),
            "only the API lane is billed"
        );
        assert_eq!(
            summary["total"]["included_usd"],
            json!(26.96),
            "grok is in the plan"
        );
        assert_eq!(summary["total"]["requests"], json!(109526));
        assert_eq!(summary["days"][0]["date"], "2026-10-02", "days ascend");
        let lanes: Vec<&str> = summary["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|lane| lane["lane"].as_str().unwrap())
            .collect();
        assert_eq!(
            lanes,
            vec!["grok", "deepseek-chat", "wemm-embedding"],
            "busiest first"
        );
        assert_eq!(summary["lanes"][0]["usd"], json!(0.0));
        assert_eq!(summary["lanes"][0]["included_usd"], json!(26.96));
        let note = summary["note"].as_str().unwrap();
        assert!(note.contains("already paid by the plan"), "{note}");
    }

    #[test]
    fn tags_read_per_seat_and_per_workload_spend_and_the_untagged_rest() {
        let tags = json!({"results": [
            {"date": "2026-10-03", "breakdown": {"entities": {
                "User-Agent: omp/18.1.18": {"metrics": {"spend": 43.84, "total_tokens": 9u64, "api_requests": 668u64}},
                "seat:sinmara": {"metrics": {"spend": 20.5, "total_tokens": 5000u64, "api_requests": 40u64}},
                "seat:gungnir": {"metrics": {"spend": 1.25, "total_tokens": 900u64, "api_requests": 12u64}},
                "workload:state-counter": {"metrics": {"spend": 0.75, "total_tokens": 10u64, "api_requests": 2u64}},
                "colin": {"metrics": {"spend": 3.0, "total_tokens": 70u64, "api_requests": 3u64}},
                "session:abc": {"metrics": {"spend": 20.5, "total_tokens": 5000u64, "api_requests": 40u64}},
            }}},
            {"date": "2026-10-02", "breakdown": {"entities": {
                "seat:gungnir": {"metrics": {"spend": 0.75, "total_tokens": 100u64, "api_requests": 1u64}}
            }}}
        ]});
        assert_eq!(
            spending_tags(&tags).into_iter().collect::<Vec<_>>(),
            [
                "colin",
                "seat:gungnir",
                "seat:sinmara",
                "session:abc",
                "workload:state-counter"
            ]
        );
        let included = BTreeMap::from([
            ("seat:sinmara".to_owned(), 20.0),
            ("session:abc".to_owned(), 20.0),
        ]);
        let seats = summarize_tags(&tags, 10.0, &included);
        let names: Vec<&str> = seats["seats"]
            .as_array()
            .unwrap()
            .iter()
            .map(|seat| seat["seat"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["sinmara", "colin (own sessions)", "gungnir"],
            "busiest first; User-Agent and workload tags are not spenders"
        );
        assert_eq!(seats["seats"][2]["usd"], json!(2.0), "summed over days");
        assert_eq!(seats["seats"][2]["requests"], json!(13));
        assert_eq!(
            seats["seats"][0]["usd"],
            json!(0.5),
            "20.5 less its 20 included"
        );
        assert_eq!(seats["seats"][0]["included_usd"], json!(20.0));
        assert_eq!(seats["untagged_usd"], json!(4.5), "10 billed - 0.5 - 3 - 2");
        assert_eq!(seats["sessions"][0]["session"], "abc");
        assert_eq!(seats["sessions"][0]["usd"], json!(0.5));
        assert_eq!(seats["sessions"][0]["included_usd"], json!(20.0));
        // Requests carry `workload:<profile>` alongside their seat tag.
        assert_eq!(
            seats["workloads"],
            json!([{"workload": "state-counter", "usd": 0.75, "included_usd": 0.0, "tokens": 10, "requests": 2}])
        );
    }
    /// A loopback gateway answering each GET path with `answer(path)`, and the paths it served.
    fn stub_gateway(
        answer: impl Fn(&str) -> String + Send + 'static,
    ) -> (String, Arc<parking_lot::Mutex<Vec<String>>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let served = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let log = Arc::clone(&served);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut buffer = [0_u8; 8192];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]);
                let path = head
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_owned();
                let body = answer(&path);
                log.lock().push(path);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (url, served)
    }

    /// One tag's `/tag/daily/activity` day: its totals and the lanes that served it.
    fn tag_day(entities: Value, lanes: Value) -> String {
        json!({"results": [{"date": "2026-10-03",
            "breakdown": {"entities": entities, "model_groups": lanes}}],
            "metadata": {"has_more": false}})
        .to_string()
    }

    fn metrics(spend: f64, requests: u64) -> Value {
        json!({"metrics": {"spend": spend, "total_tokens": requests * 10, "api_requests": requests}})
    }

    /// A book with one subscription lane (`grok`) and one API lane (`deepseek-chat`).
    fn gateway_book() -> Book {
        let account = |id: &str, billing: &str| {
            json!({"id": id, "provider": id, "billing": billing, "monthly_usd": null, "renews": null,
                   "secret": null, "keyed": true, "windows": []})
        };
        let lane = |name: &str, account: Value| {
            json!({"model_name": name, "model_info": {"odin": {"account": account, "vision": false,
                   "context_window": 1000}}})
        };
        Book::from_model_info(&json!({"data": [
            lane("grok", account("supergrok", "subscription")),
            lane("deepseek-chat", account("deepseek", "api")),
        ]}))
        .unwrap()
    }

    /// A tag whose read fails costs only its own share: the rest of the view lands, a tag read before
    /// keeps its last share, and the note says how many shares are unread and why.
    #[test]
    fn a_failed_tag_read_leaves_the_rest_of_the_view() {
        let book = gateway_book();
        let a_requests = Arc::new(parking_lot::Mutex::new(7_u64));
        let a_readable = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (seen, readable) = (Arc::clone(&a_requests), Arc::clone(&a_readable));
        let (url, _) = stub_gateway(move |path| {
            let a = *seen.lock();
            if path.starts_with("/user/daily/activity") {
                json!({"results": [{"date": "2026-10-03", "metrics": {"spend": 4.0},
                    "breakdown": {"model_groups": {"grok": metrics(3.0, 7), "deepseek-chat": metrics(1.0, 3)}}}],
                    "metadata": {"has_more": false}})
                .to_string()
            } else if path.contains("tags=seat%3Afailing-b") {
                "{}".to_owned()
            } else if path.contains("tags=seat%3Afailing-a") {
                if readable.load(std::sync::atomic::Ordering::SeqCst) {
                    tag_day(
                        json!({"seat:failing-a": metrics(3.0, a)}),
                        json!({"grok": metrics(2.0, 1)}),
                    )
                } else {
                    "{}".to_owned()
                }
            } else {
                tag_day(
                    json!({"seat:failing-a": metrics(3.0, a), "seat:failing-b": metrics(1.0, 3)}),
                    json!({}),
                )
            }
        });
        let client = crate::http_pool::default_redirect().unwrap();
        let pass = || {
            read_with_book(
                client,
                &url,
                "k",
                &book,
                1,
                Instant::now() + GATEWAY_TIMEOUT,
            )
            .unwrap()
        };
        let seat = |summary: &Value, name: &str| {
            summary["seats"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["seat"] == name)
                .unwrap()
                .clone()
        };

        let summary = pass();
        assert!(summary.get("attribution_error").is_none(), "{summary}");
        assert_eq!(seat(&summary, "failing-a")["included_usd"], json!(2.0));
        assert_eq!(
            seat(&summary, "failing-b")["usd"],
            json!(1.0),
            "unread: all billed"
        );
        let note = summary["note"].as_str().unwrap();
        assert!(note.contains("shares of 1 tag(s) are unread"), "{note}");
        assert!(note.contains("no activity rows"), "{note}");

        *a_requests.lock() = 9;
        a_readable.store(false, std::sync::atomic::Ordering::SeqCst);
        let summary = pass();
        assert_eq!(
            seat(&summary, "failing-a")["included_usd"],
            json!(2.0),
            "its last share stands"
        );
        assert!(summary["note"]
            .as_str()
            .unwrap()
            .contains("shares of 2 tag(s) are unread"));
    }
}
