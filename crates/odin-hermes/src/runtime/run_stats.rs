//! `run.stats` — measured attribution for the calling research run.
//!
//! The result is the measured snapshot `docs.render` stamps as the footer. It is
//! written to the calling pod's `/export/run-stats.json` before the model
//! compiles. A field that was not measured is null and named in
//! `unavailable`. Nothing here is filled from the requested lane, a model
//! argument, or a recollection.

use std::future::Future;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::huginn::{
    EventSeq, HistoryQuery, LiveEvent, LiveEventBody, LiveSessionId, OmpLivePlane, ToolFinished,
};
use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::pod_exec::{PodSessions, PodWorkerExec, WorkerExecFault};
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::models::Book;
use super::tools::CapabilityTool;
use super::HermesRuntime;

const TOOL: &str = "run_stats";
const SCHEMA: &str = "odin.run-stats.v1";
const STATS_FILE: &str = "run-stats.json";
const NOTE: &str =
    "snapshot as of this call; the authority writes the final measurement before the saved PDF";
const HISTORY_PAGE: u16 = 256;
/// A research run's journal is bounded by its deadline; stop before a
/// pathological history can pin the tool.
const HISTORY_EVENTS_MAX: usize = 8_192;
const WRITE_WAIT: std::time::Duration = std::time::Duration::from_secs(15);
/// The pod's export mount: the only place the renderer reads stats from.
const EXPORT_ROOT: &str = "/export/";
/// The pod binary that writes the file from stdin.
const DD: &str = "/bin/dd";
/// How much of dd's output a failure reports.
const EXEC_TAIL_BYTES: usize = 1024;
const BRIDGE_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// What the calling session's journal and the gateway can prove.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct MeasuredRun {
    pub started_at: Option<OffsetDateTime>,
    pub finished_tools: u64,
    pub saw_tool_end: bool,
    pub hosts: BTreeSet<String>,
    pub saw_web_call: bool,
    /// Deployment names from usage rows. A requested lane is not copied in.
    pub usage_models: BTreeSet<String>,
}

impl MeasuredRun {
    pub(crate) fn from_events(events: &[LiveEvent]) -> Self {
        let mut measured = Self {
            started_at: None,
            finished_tools: 0,
            saw_tool_end: false,
            hosts: BTreeSet::new(),
            saw_web_call: false,
            usage_models: BTreeSet::new(),
        };
        let mut open: BTreeMap<String, (String, Value)> = BTreeMap::new();
        for event in events {
            match &event.body {
                LiveEventBody::SessionOpened(_) => {
                    measured.started_at.get_or_insert(event.occurred_at);
                }
                LiveEventBody::Usage(usage) if !usage.model.is_empty() => {
                    measured.usage_models.insert(usage.model.clone());
                }
                LiveEventBody::ToolStarted(started) => {
                    open.insert(
                        started.tool.tool_use_id.clone(),
                        (
                            started.tool.capability_id.as_str().to_owned(),
                            started.tool.arguments.clone(),
                        ),
                    );
                }
                LiveEventBody::ToolFinished(finished) => {
                    let started = open.remove(&finished.result.tool_use_id);
                    record_finish(&mut measured, started.as_ref(), finished);
                }
                _ => {}
            }
        }
        measured
    }
}

/// Every finished invocation counts, including a failed one. `run.stats`
/// itself is the snapshot call and is not part of the run it measures.
/// A web call with no recorded https host leaves websites unmeasured.
fn record_finish(
    measured: &mut MeasuredRun,
    started: Option<&(String, Value)>,
    finished: &ToolFinished,
) {
    let capability = started
        .map(|(capability, _)| capability.as_str())
        .unwrap_or("");
    if capability == "run.stats" {
        return;
    }
    measured.saw_tool_end = true;
    measured.finished_tools += 1;
    if !matches!(capability, "web.search" | "web.read" | "browser.interact") {
        return;
    }
    let before = measured.hosts.len();
    if let Some((_, arguments)) = started {
        collect_urls(arguments, &mut measured.hosts);
    }
    if !finished.result.is_error {
        hosts_from(&finished.result.details, &mut measured.hosts);
    }
    if measured.hosts.len() > before {
        measured.saw_web_call = true;
    }
}

fn hosts_from(value: &Option<Value>, hosts: &mut BTreeSet<String>) {
    let Some(value) = value else {
        return;
    };
    collect_urls(value, hosts);
}

fn collect_urls(value: &Value, hosts: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(url) = object.get("url").and_then(Value::as_str) {
                if let Some(host) = https_host(url) {
                    hosts.insert(host);
                }
            }
            for child in object.values() {
                collect_urls(child, hosts);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_urls(item, hosts);
            }
        }
        Value::String(text) => {
            if let Ok(parsed) = serde_json::from_str::<Value>(text) {
                collect_urls(&parsed, hosts);
            }
        }
        _ => {}
    }
}

/// A public https host. Credentials, ports, paths and IP literals are not a website.
fn https_host(url: &str) -> Option<String> {
    let url = url::Url::parse(url)
        .ok()
        .filter(|url| url.scheme() == "https")?;
    let url::Host::Domain(domain) = url.host()? else {
        return None;
    };
    let host = domain.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty() && host != "localhost").then_some(host)
}

/// The renderer file. Every required key is present; unmeasured values are
/// null and listed. The requested lane is never written as `servedModel`.
pub(crate) fn stats_document(
    measured: &MeasuredRun,
    now: OffsetDateTime,
    list_price_usd: Option<f64>,
    subscription: Option<bool>,
    served_model: Option<&str>,
) -> Value {
    let wall = measured.started_at.and_then(|started| {
        let seconds = (now - started).whole_seconds();
        (seconds >= 0).then_some(seconds)
    });
    let tool_calls = measured.saw_tool_end.then_some(measured.finished_tools);
    let websites = (measured.saw_web_call && !measured.hosts.is_empty())
        .then_some(measured.hosts.len() as u64);
    let served = served_model.filter(|model| !model.is_empty());
    let mut unavailable = Vec::new();
    if list_price_usd.is_none() {
        unavailable.push("listPriceUsd");
    }
    if subscription.is_none() {
        unavailable.push("subscriptionIncluded");
    }
    if wall.is_none() {
        unavailable.push("wallSeconds");
    }
    if tool_calls.is_none() {
        unavailable.push("toolCalls");
    }
    if websites.is_none() {
        unavailable.push("websites");
    }
    if served.is_none() {
        unavailable.push("servedModel");
    }
    json!({
        "schema": SCHEMA,
        "capturedAt": rfc3339(now),
        "listPriceUsd": list_price_usd,
        "subscriptionIncluded": subscription,
        "wallSeconds": wall,
        "toolCalls": tool_calls,
        "websites": websites,
        "servedModel": served,
        "unavailable": unavailable,
    })
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unavailable".to_owned())
}

/// Pages the calling session until its head. A missing session is not a
/// zero-value run.
pub(crate) async fn read_session_events<P: OmpLivePlane + ?Sized>(
    plane: &P,
    session: &str,
) -> Result<(OffsetDateTime, Vec<LiveEvent>), String> {
    let session_id = LiveSessionId::parse(session)
        .map_err(|error| format!("session {session} is not a live session id: {error}"))?;
    let summary = plane
        .sessions(odin_domain::huginn::SessionListQuery {
            seat_id: None,
            include_ended: true,
            cursor: None,
            limit: std::num::NonZeroU16::new(128).expect("128"),
        })
        .await
        .map_err(|error| format!("live session listing failed: {error}"))?;
    let started = summary
        .sessions
        .iter()
        .find(|row| row.session_id == session_id)
        .map(|row| row.started_at);
    // The listing is paged; a session past the first page is still real.
    let started = match started {
        Some(started) => Some(started),
        None => find_started(plane, &session_id).await?,
    };
    let Some(started) = started else {
        return Err(format!(
            "no live session {session} is served; its stats are not invented"
        ));
    };
    let mut events = Vec::new();
    let mut after = EventSeq::new(0);
    loop {
        let page = plane
            .history(HistoryQuery {
                session_id,
                after,
                limit: std::num::NonZeroU16::new(HISTORY_PAGE).expect("page"),
            })
            .await
            .map_err(|error| format!("session {session} history unreadable: {error}"))?;
        if page.events.is_empty() || page.next_after == after {
            return Ok((started, events));
        }
        after = page.next_after;
        let head = page.head;
        events.extend(page.events);
        if events.len() > HISTORY_EVENTS_MAX || after >= head {
            return Ok((started, events));
        }
    }
}

async fn find_started<P: OmpLivePlane + ?Sized>(
    plane: &P,
    session: &LiveSessionId,
) -> Result<Option<OffsetDateTime>, String> {
    let mut cursor = None;
    loop {
        let page = plane
            .sessions(odin_domain::huginn::SessionListQuery {
                seat_id: None,
                include_ended: true,
                cursor,
                limit: std::num::NonZeroU16::new(128).expect("128"),
            })
            .await
            .map_err(|error| format!("live session listing failed: {error}"))?;
        if let Some(row) = page.sessions.iter().find(|row| row.session_id == *session) {
            return Ok(Some(row.started_at));
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(None),
        }
    }
}

/// One gateway model group, only when the tag names exactly one served group.
pub(crate) fn sole_served_model(groups: &BTreeMap<String, u64>) -> Option<String> {
    let mut named: Vec<&str> = groups
        .iter()
        .filter(|(_, requests)| **requests > 0)
        .map(|(group, _)| group.as_str())
        .collect();
    named.retain(|group| !group.is_empty());
    (named.len() == 1).then(|| named[0].to_owned())
}

/// List price is the gateway's own response cost. Subscription billing is
/// labelled included; API billing is billed. An unknown book entry is not
/// guessed into either.
pub(crate) fn price_label(
    spend_usd: Option<f64>,
    billing: Option<&str>,
) -> (Option<f64>, Option<bool>) {
    let spend = spend_usd.filter(|usd| usd.is_finite() && *usd >= 0.0);
    match (spend, billing) {
        (Some(usd), Some("subscription")) => (Some(round_usd(usd)), Some(true)),
        (Some(usd), Some("api")) => (Some(round_usd(usd)), Some(false)),
        _ => (None, None),
    }
}

fn round_usd(usd: f64) -> f64 {
    (usd * 100.0).round() / 100.0
}

/// Writes the exact renderer file. A short write or a nonzero `dd` is a
/// failure, not a successful stats read with a missing footer.
pub(crate) fn write_stats_file(
    exec: &dyn PodWorkerExec,
    run: &odin_domain::RunId,
    export_dir: &str,
    document: &Value,
) -> Result<String, String> {
    let path = format!("{}/{}", export_dir.trim_end_matches('/'), STATS_FILE);
    if !path.starts_with(EXPORT_ROOT) || path.contains("..") {
        return Err(format!(
            "refusing to write stats outside {EXPORT_ROOT}: {path}"
        ));
    }
    let bytes = serde_json::to_vec(document).map_err(|error| error.to_string())?;
    let argv = [DD, &format!("of={path}"), "conv=fsync", "status=none"].map(str::to_owned);
    let output = exec
        .exec(run, &argv, Some(&bytes), WRITE_WAIT, EXEC_TAIL_BYTES)
        .map_err(|fault| match fault {
            WorkerExecFault::NotStarted(reason) | WorkerExecFault::Unknown(reason) => reason,
        })?;
    if output.exit_code != 0 {
        return Err(format!(
            "writing {path} exited {}: {}",
            output.exit_code,
            String::from_utf8_lossy(&output.stderr_tail).trim()
        ));
    }
    Ok(path)
}

/// The model-facing result: the file bytes plus where they were written.
fn tool_result(document: &Value, written: &str) -> Value {
    let mut result = document.clone();
    result["written"] = json!(written);
    result["note"] = json!(NOTE);
    result
}

pub(super) fn run_stats_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Read run stats".into(),
            description: "Write this run's measured stats to /export/run-stats.json and return \
                 them. docs.render stamps the PDF footer from that file only. Call this \
                 before the authority renders. listPriceUsd is the gateway list price; \
                 subscriptionIncluded true means included, not billed. wallSeconds, toolCalls, \
                 websites and servedModel are measured. A null field named in unavailable was \
                 not measurable, and the shown value is unavailable. The served model is the \
                 gateway's served group, or the one usage model when the journal records exactly \
                 one. This snapshot is replaced by the authority's final measurement before the \
                 PDF is saved."
                .into(),
            parameters: capability_parameters!("run.stats"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(move |scope, _arguments| dispatch(&runtime, &scope)),
    )));
}

fn dispatch(runtime: &HermesRuntime, scope: &Scope) -> Result<Value, HostToolError> {
    let session = scope.session.clone().ok_or(HostToolError::Scope {
        tool: TOOL,
        reason: "a bound session is required; stats are this run's, never another session's",
    })?;
    let route = runtime
        .run_stats_route()
        .ok_or_else(|| HostToolError::unavailable(TOOL, "the run stats route is not bound"))?;
    let document = route
        .capture(session.as_str())
        .map_err(|reason| HostToolError::unavailable(TOOL, reason))?;
    let written = route
        .write(&session, &document)
        .map_err(|reason| HostToolError::unavailable(TOOL, reason))?;
    Ok(tool_result(&document, &written))
}

/// Daemon-bound capture. The tool never sees the live plane or the pod exec.
pub trait RunStatsRoute: Send + Sync {
    fn capture(&self, session: &str) -> Result<Value, String>;
    /// The capabilities the session's journal shows it calling.
    fn tools_called(&self, session: &str) -> Result<BTreeSet<String>, String>;
    fn write(&self, session: &odin_domain::SessionId, document: &Value) -> Result<String, String>;
}

/// Production route: the live plane for wall time and tool/web facts, the
/// gateway tag for cost and the served model, and the pod exec for the file.
pub struct DaemonRunStatsRoute<P> {
    pub plane: Arc<P>,
    pub gateway: Option<String>,
    pub pods: Arc<PodSessions>,
    pub exec: Arc<dyn PodWorkerExec>,
    pub handle: tokio::runtime::Handle,
}

impl<P> DaemonRunStatsRoute<P>
where
    P: OmpLivePlane + 'static,
{
    fn bridge<T: Send + 'static>(
        &self,
        future: impl Future<Output = Result<T, String>> + Send + 'static,
    ) -> Result<T, String> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let handle = self.handle.clone();
        std::thread::Builder::new()
            .name("odind-run-stats".to_owned())
            .spawn(move || {
                let _ = sender.send(handle.block_on(future));
            })
            .map_err(|error| format!("run stats bridge thread failed: {error}"))?;
        receiver
            .recv_timeout(BRIDGE_WAIT)
            .map_err(|error| format!("run stats did not return within its bound: {error}"))?
    }
}

impl<P> RunStatsRoute for DaemonRunStatsRoute<P>
where
    P: OmpLivePlane + 'static,
{
    fn capture(&self, session: &str) -> Result<Value, String> {
        let plane = Arc::clone(&self.plane);
        let session = session.to_owned();
        let gateway = self.gateway.clone();
        self.bridge(async move {
            let (started, events) = read_session_events(plane.as_ref(), &session).await?;
            let mut measured = MeasuredRun::from_events(&events);
            measured.started_at.get_or_insert(started);
            let now = OffsetDateTime::now_utc();
            let since_ms = u64::try_from(started.unix_timestamp().max(0) * 1000).unwrap_or(0);
            let tag = format!("{}{session}", odin_omp::SESSION_SPEND_TAG_PREFIX);
            let (price, served, billing) = match gateway.as_deref() {
                Some(gateway) => gateway_facts(gateway, &tag, since_ms)?,
                None => (None, None, None),
            };
            let served = served.or_else(|| sole_usage_model(&measured.usage_models));
            let (list_price, included) = price_label(price, billing.as_deref());
            Ok(stats_document(
                &measured,
                now,
                list_price,
                included,
                served.as_deref(),
            ))
        })
    }

    fn tools_called(&self, session: &str) -> Result<BTreeSet<String>, String> {
        let plane = Arc::clone(&self.plane);
        let session = session.to_owned();
        self.bridge(async move {
            let (_, events) = read_session_events(plane.as_ref(), &session).await?;
            Ok(tools_called(&events))
        })
    }

    fn write(&self, session: &odin_domain::SessionId, document: &Value) -> Result<String, String> {
        let target = self.pods.target_of(session).ok_or_else(|| {
            "this session has no workload pod; run stats are not written anywhere else".to_owned()
        })?;
        write_stats_file(
            self.exec.as_ref(),
            &target.run,
            &target.export_dir,
            document,
        )
    }
}

/// Every capability the events show the session calling, `run.stats` aside.
fn tools_called(events: &[LiveEvent]) -> BTreeSet<String> {
    events
        .iter()
        .filter_map(|event| match &event.body {
            LiveEventBody::ToolStarted(started) => Some(started.tool.capability_id.as_str()),
            _ => None,
        })
        .filter(|capability| *capability != "run.stats")
        .map(str::to_owned)
        .collect()
}

fn sole_usage_model(models: &BTreeSet<String>) -> Option<String> {
    (models.len() == 1)
        .then(|| models.iter().next().cloned())
        .flatten()
}

type GatewayFacts = (Option<f64>, Option<String>, Option<String>);

/// Spend and the served group for one session tag. A gateway that cannot
/// answer leaves those fields unavailable; it does not fail the wall/tool
/// reading, and it does not invent a zero.
fn gateway_facts(gateway: &str, tag: &str, since_ms: u64) -> Result<GatewayFacts, String> {
    let unavailable = |reason: String| {
        tracing::warn!("odin-hermes: run.stats has no gateway facts for {tag}: {reason}");
        Ok((None, None, None))
    };
    let key = match super::gateway::key() {
        Ok(key) => key,
        Err(reason) => return unavailable(reason),
    };
    let activity = match super::spend::tag_activity(
        gateway,
        &key,
        tag,
        since_ms,
        super::spend::GATEWAY_TIMEOUT,
    ) {
        Ok(activity) => activity,
        Err(reason) => return unavailable(reason),
    };
    let groups = super::spend::served_model_groups(&activity);
    let served = sole_served_model(&groups);
    let spend = tag_spend(&activity, tag);
    let billing = match (spend, served.as_deref()) {
        (Some(_), Some(group)) => book_billing(gateway, &key, group),
        _ => None,
    };
    Ok((spend, served, billing))
}

fn tag_spend(activity: &Value, tag: &str) -> Option<f64> {
    let mut spend = 0.0;
    let mut seen = false;
    let days = activity.get("results").and_then(Value::as_array)?;
    for day in days {
        let metrics = day
            .pointer("/breakdown/entities")
            .and_then(|entities| entities.get(tag))
            .and_then(|entry| entry.get("metrics"))
            .or_else(|| day.get("metrics"));
        let Some(metrics) = metrics else {
            continue;
        };
        let Some(value) = metrics.get("spend").and_then(Value::as_f64) else {
            continue;
        };
        if !value.is_finite() || value < 0.0 {
            return None;
        }
        seen = true;
        spend += value;
    }
    seen.then_some(spend)
}

/// How the model book bills `group`; unreadable, it is left out and the cause logged.
fn book_billing(gateway: &str, key: &str, group: &str) -> Option<String> {
    let read = || -> Result<Book, String> {
        let client = crate::http_pool::default_redirect()
            .map_err(|error| format!("gateway client: {error}"))?;
        let info = super::spend::fetch(
            client,
            gateway,
            key,
            "/model/info",
            super::spend::GATEWAY_TIMEOUT,
        )?;
        Book::from_model_info(&info)
    };
    match read() {
        Ok(book) => book.billing(group).map(str::to_owned),
        Err(reason) => {
            tracing::warn!(
                "odin-hermes: run.stats cannot read the model book for {group}: {reason}"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::huginn::{LiveContentBlock, ToolResultBlock, ToolStarted, ToolUseBlock};
    use odin_domain::{CapabilityId, EventId, TurnId};

    fn event(body: LiveEventBody) -> LiveEvent {
        LiveEvent {
            schema_version: 1,
            event_id: EventId::new("event:stats").unwrap(),
            session_id: LiveSessionId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
            epoch: odin_domain::huginn::SessionEpoch::new(1),
            sequence: EventSeq::new(1),
            occurred_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            body,
        }
    }

    fn started(id: &str, capability: &str, arguments: Value) -> LiveEvent {
        event(LiveEventBody::ToolStarted(ToolStarted {
            turn_id: TurnId::new("turn:1").unwrap(),
            tool: ToolUseBlock {
                tool_use_id: id.to_owned(),
                capability_id: CapabilityId::new(capability).unwrap(),
                arguments,
            },
            intent: None,
        }))
    }

    fn finished(id: &str, details: Value) -> LiveEvent {
        event(LiveEventBody::ToolFinished(ToolFinished {
            turn_id: TurnId::new("turn:1").unwrap(),
            result: ToolResultBlock {
                tool_use_id: id.to_owned(),
                content: vec![LiveContentBlock::Text("ok".to_owned())],
                is_error: false,
                details: Some(details),
            },
        }))
    }

    #[test]
    fn the_methods_a_pod_tried_are_the_capabilities_its_journal_shows_it_calling() {
        let events = [
            started("a", "web.read", json!({})),
            started("b", "web.read", json!({})),
            started("c", "browser.observe", json!({})),
            started("d", "run.stats", json!({})),
        ];
        assert_eq!(
            tools_called(&events),
            BTreeSet::from(["browser.observe".to_owned(), "web.read".to_owned()])
        );
    }

    #[test]
    fn finished_web_calls_count_distinct_https_hosts_and_skip_this_tool() {
        let events = [
            started("search", "web.search", json!({})),
            finished(
                "search",
                json!({"results": [
                    {"url": "https://Example.com/a"},
                    {"url": "https://example.com/b"},
                    {"url": "http://insecure.example/no"},
                    {"url": "https://other.example/c"}
                ]}),
            ),
            started(
                "read",
                "web.read",
                json!({"url": "https://docs.example/page"}),
            ),
            finished("read", json!({"content": [{"text": "body"}]})),
            started("stats", "run.stats", json!({})),
            finished("stats", json!({})),
            started(
                "broken",
                "web.search",
                json!({"url": "https://failed.example/q"}),
            ),
            event(LiveEventBody::ToolFinished(ToolFinished {
                turn_id: TurnId::new("turn:1").unwrap(),
                result: ToolResultBlock {
                    tool_use_id: "broken".to_owned(),
                    content: vec![LiveContentBlock::Text("no".to_owned())],
                    is_error: true,
                    details: Some(json!({"results": [{"url": "https://hidden.example"}]})),
                },
            })),
            started("opaque", "web.read", json!({})),
            finished("opaque", json!({"content": [{"text": "no url recorded"}]})),
        ];
        let measured = MeasuredRun::from_events(&events);
        assert_eq!(
            measured.finished_tools, 4,
            "failed invocations still finished"
        );
        assert_eq!(
            measured.hosts.iter().cloned().collect::<Vec<_>>(),
            [
                "docs.example",
                "example.com",
                "failed.example",
                "other.example"
            ]
        );
        let document = stats_document(
            &measured,
            OffsetDateTime::UNIX_EPOCH,
            Some(1.25),
            Some(true),
            Some("groq/openai/gpt-oss-120b"),
        );
        assert_eq!(document["toolCalls"], 4);
        assert_eq!(document["websites"], 4);
        assert_eq!(document["servedModel"], "groq/openai/gpt-oss-120b");
        assert_eq!(document["subscriptionIncluded"], true);
        assert_eq!(document["unavailable"], json!(["wallSeconds"]));
    }

    /// One recorded pod exec: its argv and what it was given on stdin.
    type Exec = (Vec<String>, Option<Vec<u8>>);

    /// Records the one write a run's stats make into the pod.
    struct RecordingExec {
        exit_code: i32,
        calls: parking_lot::Mutex<Vec<Exec>>,
    }

    impl PodWorkerExec for RecordingExec {
        fn exec(
            &self,
            _run: &odin_domain::RunId,
            argv: &[String],
            stdin: Option<&[u8]>,
            _wait: std::time::Duration,
            _tail_bytes: usize,
        ) -> Result<odin_omp::host_tools::pod_exec::WorkerOutput, WorkerExecFault> {
            self.calls
                .lock()
                .push((argv.to_vec(), stdin.map(<[u8]>::to_vec)));
            Ok(odin_omp::host_tools::pod_exec::WorkerOutput {
                exit_code: self.exit_code,
                stdout_tail: Vec::new(),
                stderr_tail: b"dd: no space left on device\n".to_vec(),
                stdout_bytes: 0,
                stderr_bytes: 0,
            })
        }
    }

    #[test]
    fn the_stats_file_lands_whole_in_the_export_and_a_failed_write_says_why() {
        let run = odin_domain::RunId::new("run-1").unwrap();
        let document = json!({"toolCalls": 4, "websites": null});
        let exec = RecordingExec {
            exit_code: 0,
            calls: Default::default(),
        };
        let path = write_stats_file(&exec, &run, "/export/", &document).unwrap();
        assert_eq!(path, "/export/run-stats.json");
        let calls = exec.calls.lock();
        let [(argv, stdin)] = calls.as_slice() else {
            panic!("one write: {calls:?}");
        };
        assert_eq!(argv[..2], ["/bin/dd", "of=/export/run-stats.json"]);
        assert_eq!(
            serde_json::from_slice::<Value>(stdin.as_deref().unwrap()).unwrap(),
            document
        );
        drop(calls);

        let full = RecordingExec {
            exit_code: 1,
            calls: Default::default(),
        };
        let error = write_stats_file(&full, &run, "/export", &document).unwrap_err();
        assert!(
            error.contains("exited 1") && error.contains("no space left on device"),
            "{error}"
        );
        let outside = write_stats_file(&full, &run, "/tmp/export/../..", &document).unwrap_err();
        assert!(outside.contains("outside /export"), "{outside}");
        assert_eq!(full.calls.lock().len(), 1, "the refused path ran nothing");
    }
}
