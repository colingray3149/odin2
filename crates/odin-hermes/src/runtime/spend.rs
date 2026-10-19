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
//! sends it as `x-litellm-tags`), and Colin's own OMP sessions `colin`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::tools::{object_schema, CapabilityTool};
use super::HermesRuntime;

const TOOL: &str = "spend_read";
const GATEWAY: &str = "http://127.0.0.1:4000";
const KEY_ENV: &str = "LITELLM_MASTER_KEY";
const DEFAULT_DAYS: i64 = 7;
const MAX_DAYS: i64 = 31;

fn unavailable(reason: impl Into<String>) -> HostToolError {
    HostToolError::Unavailable {
        tool: TOOL,
        reason: reason.into(),
    }
}

/// Upstream model id -> the lane name(s) that route to it, from
/// `/model/info`. Two lanes on one model (zai-glm and go-glm) share a key.
pub(crate) fn lanes_by_model(model_info: &Value) -> BTreeMap<String, String> {
    let mut lanes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in model_info
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (Some(lane), Some(model)) = (
            entry.get("model_name").and_then(Value::as_str),
            entry
                .pointer("/litellm_params/model")
                .and_then(Value::as_str),
        ) else {
            continue;
        };
        let names = lanes.entry(model.to_owned()).or_default();
        if !names.iter().any(|name| name == lane) {
            names.push(lane.to_owned());
        }
    }
    lanes
        .into_iter()
        .map(|(model, mut names)| {
            names.sort();
            (model, names.join("/"))
        })
        .collect()
}

#[derive(Default)]
struct Tally {
    usd: f64,
    tokens: u64,
    requests: u64,
}

impl Tally {
    fn add(&mut self, metrics: &Value) {
        self.usd += metrics.get("spend").and_then(Value::as_f64).unwrap_or(0.0);
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
        json!({
            "usd": (self.usd * 100.0).round() / 100.0,
            "tokens": self.tokens,
            "requests": self.requests,
        })
    }
}

/// The owner-facing summary of `/user/daily/activity` results: per day,
/// per lane (busiest first), and in total.
pub(crate) fn summarize(
    activity: &Value,
    lanes: &BTreeMap<String, String>,
    from: &str,
    to: &str,
) -> Value {
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
            tally.add(metrics);
            total.add(metrics);
        }
        if let Some(models) = day.pointer("/breakdown/models").and_then(Value::as_object) {
            for (model, entry) in models {
                let lane = lanes.get(model).cloned().unwrap_or_else(|| model.clone());
                if let Some(metrics) = entry.get("metrics") {
                    per_lane.entry(lane).or_default().add(metrics);
                }
            }
        }
        let mut row = tally.json();
        row["date"] = day.get("date").cloned().unwrap_or(Value::Null);
        days.push(row);
    }
    days.sort_by(|a, b| a["date"].as_str().cmp(&b["date"].as_str()));
    let mut lanes: Vec<(String, Tally)> = per_lane.into_iter().collect();
    lanes.sort_by(|(_, a), (_, b)| {
        b.usd
            .partial_cmp(&a.usd)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.tokens.cmp(&a.tokens))
    });
    let lane_names = lanes
        .iter()
        .map(|(lane, _)| lane.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let listed = if lane_names.is_empty() {
        "none".to_owned()
    } else {
        lane_names
    };
    json!({
        "from": from,
        "to": to,
        "total": total.json(),
        "days": days,
        "lanes": lanes
            .into_iter()
            .map(|(lane, tally)| {
                let mut row = tally.json();
                row["lane"] = json!(lane);
                row
            })
            .collect::<Vec<_>>(),
        "note": format!(
            "USD is each lane's declared API list price applied to its tokens. \
             Lanes in this window: {listed}. No spending cap is set."
        ),
    })
}

/// The spend tag a seat's requests carry, as the owner reads it: `seat:<id>`
/// is the seat, `colin` is Colin's own OMP sessions. Every other tag
/// (LiteLLM's automatic `User-Agent: …`, `workload:<profile>`,
/// `session:<id>`) is not a spender and is skipped.
fn spender(tag: &str) -> Option<String> {
    if let Some(seat) = tag.strip_prefix("seat:") {
        return (!seat.is_empty()).then(|| seat.to_owned());
    }
    (tag == "colin").then(|| "colin (own sessions)".to_owned())
}

/// Busiest first, each row labelled under `key`.
fn ranked(tallies: BTreeMap<String, Tally>, key: &str) -> Vec<Value> {
    let mut rows: Vec<(String, Tally)> = tallies.into_iter().collect();
    rows.sort_by(|(_, a), (_, b)| {
        b.usd
            .partial_cmp(&a.usd)
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
/// (busiest first), plus the remainder of `total_usd` no seat tag accounts
/// for (embeddings, requests from before tagging, tools that call the
/// gateway directly). A pod session's requests carry its seat and
/// `workload:<profile>`, so the workloads answer "what did this pod cost"
/// within their seats' totals.
pub(crate) fn summarize_tags(tag_activity: &Value, total_usd: f64) -> Value {
    let mut per_seat: BTreeMap<String, Tally> = BTreeMap::new();
    let mut per_workload: BTreeMap<String, Tally> = BTreeMap::new();
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
                per_seat.entry(seat).or_default().add(metrics);
            } else if let Some(profile) = tag.strip_prefix("workload:").filter(|p| !p.is_empty()) {
                per_workload
                    .entry(profile.to_owned())
                    .or_default()
                    .add(metrics);
            }
        }
    }
    let attributed: f64 = per_seat.values().map(|tally| tally.usd).sum();
    json!({
        "seats": ranked(per_seat, "seat"),
        "workloads": ranked(per_workload, "workload"),
        "untagged_usd": (((total_usd - attributed).max(0.0)) * 100.0).round() / 100.0,
    })
}

fn fetch(
    client: &reqwest::blocking::Client,
    key: &str,
    path: &str,
    timeout: Duration,
) -> Result<Value, String> {
    let response = client
        .get(format!("{GATEWAY}{path}"))
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

/// Daily activity is paginated over (day, entity, model) rows, ten per page by default.
const ACTIVITY_PAGE_SIZE: u32 = 500;
/// A bound on the pages one view reads.
const ACTIVITY_MAX_PAGES: u32 = 40;

/// Every page of one daily-activity view, merged into one `results` array.
fn fetch_all_pages(
    client: &reqwest::blocking::Client,
    key: &str,
    path: &str,
    timeout: Duration,
) -> Result<Value, String> {
    let mut pages = Vec::new();
    for page in 1..=ACTIVITY_MAX_PAGES {
        let value = fetch(
            client,
            key,
            &format!("{path}&page_size={ACTIVITY_PAGE_SIZE}&page={page}"),
            timeout,
        )?;
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
pub fn read_gateway_spend(days: i64) -> Result<Value, String> {
    if !(1..=MAX_DAYS).contains(&days) {
        return Err(format!("days must be 1..={MAX_DAYS}"));
    }
    read(days).map_err(|error| error.to_string())
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

/// Reports model groups that served tagged requests since `since_ms`, including fallback lanes.
pub fn read_tag_model_groups(tag: &str, since_ms: u64) -> Result<BTreeMap<String, u64>, String> {
    let key = std::env::var(KEY_ENV)
        .ok()
        .filter(|key| !key.is_empty())
        .ok_or_else(|| "the gateway credential is not configured on this host".to_owned())?;
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
        &key,
        &format!("/tag/daily/activity?tags={tag}&start_date={from}&end_date={to}"),
        Duration::from_secs(10),
    )
    .map(|activity| served_model_groups(&activity))
}

fn read(days: i64) -> Result<Value, HostToolError> {
    let key = std::env::var(KEY_ENV)
        .ok()
        .filter(|key| !key.is_empty())
        .ok_or_else(|| unavailable("the gateway credential is not configured on this host"))?;
    let today = time::OffsetDateTime::now_utc().date();
    let from = today - time::Duration::days(days - 1);
    let client = crate::http_pool::default_redirect()
        .map_err(|error| unavailable(format!("gateway client: {error}")))?;
    let model_info =
        fetch(client, &key, "/model/info", Duration::from_secs(30)).map_err(unavailable)?;
    let activity = fetch_all_pages(
        client,
        &key,
        &format!("/user/daily/activity?start_date={from}&end_date={today}"),
        Duration::from_secs(30),
    )
    .map_err(unavailable)?;
    let mut summary = summarize(
        &activity,
        &lanes_by_model(&model_info),
        &from.to_string(),
        &today.to_string(),
    );
    let total_usd = activity
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|day| day.pointer("/metrics/spend").and_then(Value::as_f64))
        .sum::<f64>();
    // Per-seat attribution is additive: an unreadable tag view leaves the
    // per-day/per-lane answer intact and says why the seats are missing.
    match fetch_all_pages(
        client,
        &key,
        &format!("/tag/daily/activity?start_date={from}&end_date={today}"),
        Duration::from_secs(30),
    ) {
        Ok(tags) => {
            let tags = summarize_tags(&tags, total_usd);
            summary["seats"] = tags["seats"].clone();
            summary["workloads"] = tags["workloads"].clone();
            summary["untagged_usd"] = tags["untagged_usd"].clone();
        }
        Err(error) => {
            tracing::warn!(error = %error, "odin-hermes: spend read per-seat view unavailable: {error}");
            summary["seats"] = json!(format!("per-seat view unavailable: {error}"));
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

pub(super) fn spend_tools(_runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
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
        read(days)
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Read model spend".into(),
            description:
                "What the model gateway spent over the last `days` days (default 7, \
                 at most 31): dollars at each lane's declared price, tokens and requests, per \
                 day, per lane, per seat and per pod workload, with the total. Use it for 'what did this week cost?'."
                    .into(),
            parameters: object_schema(
                TOOL,
                json!({ "days": { "type": "integer", "minimum": 1, "maximum": MAX_DAYS } }),
                &[],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}

#[cfg(test)]
mod tests {
    #[test]
    fn seats_on_a_later_page_are_attributed() {
        let page = |tags: Value, more: bool| {
            json!({"results": [{"date": "2026-10-03", "breakdown": {"entities": tags}}],
                   "metadata": {"has_more": more}})
        };
        let first = page(
            json!({"session:a": {"metrics": {"spend": 1.0, "total_tokens": 1u64, "api_requests": 1u64}}}),
            true,
        );
        let second = page(
            json!({"seat:kubert": {"metrics": {"spend": 2.5, "total_tokens": 10u64, "api_requests": 2u64}}}),
            false,
        );
        let merged = merge_activity_pages(vec![first.clone(), second]);
        let seats = summarize_tags(&merged, 3.5);
        assert!(seats.to_string().contains("kubert"), "{seats}");
        let only_first = summarize_tags(&merge_activity_pages(vec![first]), 3.5);
        assert!(!only_first.to_string().contains("kubert"));
    }

    use super::*;

    /// LiteLLM 1.97 `/model/info` and `/user/daily/activity` response shapes.
    #[test]
    fn a_week_of_gateway_activity_reads_per_day_and_per_lane() {
        let model_info = json!({"data": [
            {"model_name": "astra", "litellm_params": {"model": "openai/gpt-6-astra"}},
            {"model_name": "zai-glm", "litellm_params": {"model": "openai/glm-5.3"}},
            {"model_name": "go-glm", "litellm_params": {"model": "openai/glm-5.3"}},
            {"model_name": "kimi-k28", "litellm_params": {"model": "openai/kimi-for-coding"}},
        ]});
        let activity = json!({"results": [
            {"date": "2026-10-03", "metrics": {"spend": 29.6947, "total_tokens": 21598338u64, "api_requests": 109525u64},
             "breakdown": {"models": {
                "openai/gpt-6-astra": {"metrics": {"spend": 26.958, "total_tokens": 9000000u64, "api_requests": 300u64}},
                "openai/glm-5.3": {"metrics": {"spend": 2.737, "total_tokens": 1200000u64, "api_requests": 90u64}},
                "openai/WeMM-Embedding-2B": {"metrics": {"spend": 0.0, "total_tokens": 9057271u64, "api_requests": 109000u64}}
             }}},
            {"date": "2026-10-02", "metrics": {"spend": 0.00043, "total_tokens": 100u64, "api_requests": 1u64},
             "breakdown": {"models": {
                "openai/kimi-for-coding": {"metrics": {"spend": 0.0, "total_tokens": 100u64, "api_requests": 1u64}}
             }}}
        ]});
        let summary = summarize(
            &activity,
            &lanes_by_model(&model_info),
            "2026-09-27",
            "2026-10-03",
        );
        assert_eq!(
            summary["total"]["usd"],
            json!(29.7),
            "29.6947 + 0.00043, to the cent"
        );
        assert_eq!(summary["total"]["requests"], json!(109526));
        assert_eq!(summary["days"][0]["date"], "2026-10-02", "days ascend");
        assert_eq!(summary["days"][1]["usd"], json!(29.69));
        let lanes: Vec<&str> = summary["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|lane| lane["lane"].as_str().unwrap())
            .collect();
        assert_eq!(
            lanes,
            vec![
                "astra",
                "go-glm/zai-glm",
                "openai/WeMM-Embedding-2B",
                "kimi-k28"
            ],
            "busiest first; a model two lanes share names both; an unmapped model keeps its id"
        );
        assert_eq!(summary["lanes"][0]["usd"], json!(26.96));
    }

    /// LiteLLM 1.97 tags appear under `breakdown.entities`, including automatic User-Agent tags.
    #[test]
    fn a_session_tag_reads_the_lanes_that_really_served_it() {
        // LiteLLM 1.97 `/tag/daily/activity?tags=session:<id>`: the model
        // groups that answered (a fallback answers under its own group).
        let activity = json!({"results": [
            {"date": "2026-10-03", "breakdown": {"model_groups": {
                "zai-glm": {"metrics": {"spend": 0.0, "api_requests": 12u64}},
                "glm-flash": {"metrics": {"spend": 0.0, "api_requests": 3u64}}
            }}},
            {"date": "2026-10-04", "breakdown": {"model_groups": {
                "zai-glm": {"metrics": {"spend": 0.0, "api_requests": 5u64}}
            }}}
        ]});
        assert_eq!(
            served_model_groups(&activity),
            BTreeMap::from([("glm-flash".to_owned(), 3), ("zai-glm".to_owned(), 17)])
        );
        assert!(served_model_groups(&json!({"results": []})).is_empty());
    }

    #[test]
    fn tags_read_per_seat_and_per_workload_spend_and_the_untagged_rest() {
        let tags = json!({"results": [
            {"date": "2026-10-03", "breakdown": {"entities": {
                "User-Agent: omp/18.1.18": {"metrics": {"spend": 43.84, "total_tokens": 9u64, "api_requests": 668u64}},
                "seat:sinmara": {"metrics": {"spend": 20.5, "total_tokens": 5000u64, "api_requests": 40u64}},
                "seat:gungnir": {"metrics": {"spend": 1.25, "total_tokens": 900u64, "api_requests": 12u64}},
                "workload:state-counter": {"metrics": {"spend": 0.75, "total_tokens": 10u64, "api_requests": 2u64}},
                "colin": {"metrics": {"spend": 3.0, "total_tokens": 70u64, "api_requests": 3u64}}
            }}},
            {"date": "2026-10-02", "breakdown": {"entities": {
                "seat:gungnir": {"metrics": {"spend": 0.75, "total_tokens": 100u64, "api_requests": 1u64}}
            }}}
        ]});
        let seats = summarize_tags(&tags, 30.0);
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
        assert_eq!(seats["untagged_usd"], json!(4.5), "30 - 20.5 - 3 - 2");
        // Requests carry `workload:<profile>` alongside their seat tag.
        assert_eq!(
            seats["workloads"],
            json!([{"workload": "state-counter", "usd": 0.75, "tokens": 10, "requests": 2}])
        );
    }
}
