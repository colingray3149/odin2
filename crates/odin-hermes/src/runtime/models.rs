//! The model book read back from the gateway: every account and lane the owner declared (dotfiles
//! `gateway-lanes.nix`, served in LiteLLM's `/model/info` as `model_info.odin`), each class's
//! order, and how much of each account's declared windows is used. One reading answers
//! `models.read`, `odin models` and the class router.

use super::tools::NO_GATEWAY;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use odin_domain::Scope;
use odin_kernel::provider::class::{pick, ClassLane, Needs};
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde::Deserialize;
use serde_json::{json, Value};

use super::gateway;
use super::spend::{fetch, fetch_all_pages};
use super::tools::CapabilityTool;
use super::HermesRuntime;

mod sources;

const TOOL: &str = "models_read";
/// A window counts as used up at this share, so a turn never starts on a nearly spent plan.
const HOLD_AT: f64 = 0.9;
/// A held account takes work again once its windows are below this share, so lanes don't flap.
const RETURN_AT: f64 = 0.75;
/// How long one reading answers every caller before the gateway is read again.
const READING_TTL: Duration = Duration::from_secs(60);
/// How long a provider refusal holds its account, whatever the gateway's windows say.
const REFUSAL_HOLD: Duration = Duration::from_secs(30 * 60);
const GATEWAY_READING_TIMEOUT: Duration = Duration::from_secs(17);
const MODEL_INFO_TIMEOUT: Duration = Duration::from_secs(3);
/// How long startup waits between gateway readiness attempts while LiteLLM
/// is still coming up.
const READINESS_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Spend-log rows per page (LiteLLM's maximum).
const LOG_PAGE: u32 = 1000;
/// The local model list (`[models] local_list`), set once when odind starts.
static LOCAL_LIST: OnceLock<PathBuf> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct Window {
    pub span: String,
    pub usd: Option<f64>,
    pub requests: Option<u64>,
    /// Provider throughput guidance, not a quota. Still visible alongside measured requests.
    #[serde(default)]
    pub requests_estimate: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct Account {
    pub id: String,
    pub provider: String,
    pub billing: String,
    pub monthly_usd: Option<f64>,
    pub renews: Option<String>,
    pub secret: Option<String>,
    pub keyed: bool,
    pub windows: Vec<Window>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Lane {
    pub account: String,
    pub vision: bool,
    pub context_window: u64,
}

#[derive(Deserialize)]
struct ClassInfo {
    name: String,
    order: Vec<String>,
}

#[derive(Deserialize)]
struct OdinInfo {
    account: Account,
    vision: bool,
    context_window: u64,
    #[serde(default)]
    class: Option<ClassInfo>,
}

/// The declared book: accounts, lanes (by gateway model group) and classes in order.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Book {
    pub accounts: BTreeMap<String, Account>,
    pub lanes: BTreeMap<String, Lane>,
    pub classes: BTreeMap<String, Vec<String>>,
}

impl Book {
    pub(crate) fn from_model_info(model_info: &Value) -> Result<Self, String> {
        let mut book = Self::default();
        for entry in model_info
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(group) = entry.get("model_name").and_then(Value::as_str) else {
                continue;
            };
            let Some(odin) = entry.pointer("/model_info/odin") else {
                continue;
            };
            let odin = OdinInfo::deserialize(odin).map_err(|error| {
                format!("gateway lane {group} has an unreadable odin model_info: {error}")
            })?;
            match odin.class {
                Some(class) => {
                    book.classes.insert(class.name, class.order);
                }
                None => {
                    book.lanes.insert(
                        group.to_owned(),
                        Lane {
                            account: odin.account.id.clone(),
                            vision: odin.vision,
                            context_window: odin.context_window,
                        },
                    );
                    book.accounts.insert(odin.account.id.clone(), odin.account);
                }
            }
        }
        if book.lanes.is_empty() {
            return Err(
                "the gateway's /model/info carries no declared lanes (model_info.odin)".to_owned(),
            );
        }
        Ok(book)
    }

    /// Adds the local family's members: one lane and one account each, so a member holds alone.
    fn add_local_family(&mut self, members: &[LocalMember]) {
        for member in members {
            let lane = member.lane();
            self.lanes.insert(
                lane.clone(),
                Lane {
                    account: lane.clone(),
                    vision: member.vision,
                    context_window: member.context,
                },
            );
            self.accounts.insert(
                lane.clone(),
                Account {
                    id: lane,
                    provider: "local".to_owned(),
                    billing: "local".to_owned(),
                    monthly_usd: None,
                    renews: None,
                    secret: None,
                    keyed: true,
                    windows: Vec::new(),
                },
            );
        }
    }

    /// The billing of a gateway model group: a lane, or a class served by its first lane.
    pub(crate) fn billing(&self, group: &str) -> Option<&str> {
        let lane = self
            .lanes
            .get(group)
            .or_else(|| self.lanes.get(self.classes.get(group)?.first()?))?;
        Some(self.accounts.get(&lane.account)?.billing.as_str())
    }

    /// Every model group whose requests an account served: its lanes, and the classes they head.
    fn groups_of(&self, account: &str) -> Vec<String> {
        let mut groups: Vec<String> = self
            .lanes
            .iter()
            .filter(|(_, lane)| lane.account == account)
            .map(|(name, _)| name.clone())
            .collect();
        groups.extend(
            self.classes
                .iter()
                .filter(|(_, order)| order.first().is_some_and(|first| groups.contains(first)))
                .map(|(class, _)| class.clone())
                .collect::<Vec<_>>(),
        );
        groups
    }

    /// One lane as the router sees it, with its account's hold.
    fn lane_state(&self, name: &str, holds: &BTreeMap<String, String>) -> Option<ClassLane> {
        let lane = self.lanes.get(name)?;
        Some(ClassLane {
            lane: name.to_owned(),
            vision: lane.vision,
            context_window: lane.context_window,
            held: holds.get(&lane.account).cloned(),
        })
    }

    /// A class's lanes in order, each with its account's hold.
    pub(crate) fn class_lanes(
        &self,
        class: &str,
        holds: &BTreeMap<String, String>,
    ) -> Option<Vec<ClassLane>> {
        Some(
            self.classes
                .get(class)?
                .iter()
                .filter_map(|name| self.lane_state(name, holds))
                .collect(),
        )
    }

    fn validate_launches<'a>(&self, launches: impl Iterator<Item = &'a str>) -> Result<(), String> {
        let launches: BTreeSet<&str> = launches.collect();
        for class in ["fast", "standard", "strong"] {
            let order = self
                .classes
                .get(class)
                .filter(|order| !order.is_empty())
                .ok_or_else(|| format!("class {class} has no declared lane order"))?;
            for lane in order {
                if !self.lanes.contains_key(lane) {
                    return Err(format!("class {class} names undeclared lane {lane}"));
                }
                if !launches.contains(lane.as_str()) {
                    return Err(format!(
                        "class {class} lane {lane} is not in this seat's launch declarations"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The local model list `local-models scan` writes.
#[derive(Deserialize)]
struct LocalList {
    models: Vec<LocalModel>,
}

/// One entry of the local model list. The router loads a model on its first request, so a listed
/// model is always callable; only a mode that stops the router holds it.
#[derive(Deserialize)]
struct LocalModel {
    id: String,
    kind: String,
    context: Option<u64>,
}

/// A chat or vision model on the local list, a member of the local family.
#[derive(Clone, Debug, PartialEq)]
pub struct LocalMember {
    pub id: String,
    pub vision: bool,
    pub context: u64,
    /// Why the member is held now (a mode that stops the router); `None` when it can take work.
    pub hold: Option<String>,
}

impl LocalMember {
    /// The member's lane and account name, `local/<id>`.
    pub fn lane(&self) -> String {
        format!("{}/{}", odin_registry::LOCAL_ACCOUNT, self.id)
    }
}

/// Declares the local model list the local family expands; odind sets it once at start.
pub fn set_local_list(path: PathBuf) {
    let _ = LOCAL_LIST.set(path);
}

/// The local family's members from the declared list, each with its hold. No list declared, no
/// members; an unreadable list names its path and how to refresh it.
pub fn local_family() -> Result<Vec<LocalMember>, String> {
    let Some(path) = LOCAL_LIST.get() else {
        return Ok(Vec::new());
    };
    let text = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "local model list {} is unreadable: {error}; run local-models scan on the authority",
            path.display()
        )
    })?;
    let list: LocalList = serde_json::from_str(&text).map_err(|error| {
        format!(
            "local model list {} is not the local-models scan output: {error}",
            path.display()
        )
    })?;
    let mode = local_mode(path)?;
    Ok(family_members(list.models, mode.as_deref()))
}

/// Mini's mode when it is not `odin`, as a hold: `local-models mode` keeps one `mode.<name>`
/// beside the list, holding when that mode began, and none in `odin`.
fn local_mode(list: &Path) -> Result<Option<String>, String> {
    let dir = list.parent().unwrap_or(Path::new("."));
    let entries = std::fs::read_dir(dir)
        .map_err(|error| format!("the local mode in {} is unreadable: {error}", dir.display()))?;
    for entry in entries.flatten() {
        let file = entry.file_name();
        let Some(name) = file.to_str().and_then(|file| file.strip_prefix("mode.")) else {
            continue;
        };
        let since = std::fs::read_to_string(entry.path())
            .map_err(|error| format!("local mode {name} is unreadable: {error}"))?;
        return Ok(Some(format!(
            "the local models are off: {name} mode since {}",
            since.trim()
        )));
    }
    Ok(None)
}

/// The chat and vision models of a list as members; a mode that stops the router holds them all.
fn family_members(models: Vec<LocalModel>, mode: Option<&str>) -> Vec<LocalMember> {
    models
        .into_iter()
        .filter(|model| matches!(model.kind.as_str(), "chat" | "vision"))
        .map(|model| LocalMember {
            hold: mode.map(str::to_owned),
            vision: model.kind == "vision",
            id: model.id,
            context: model.context.unwrap_or_default(),
        })
        .collect()
}

/// How much of one window is used.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Used {
    pub usd: f64,
    pub requests: u64,
}

impl Used {
    /// Why the window holds its account, when it is (nearly) used up; an account `held` by the
    /// last reading stays held until the window is below `RETURN_AT`.
    pub(crate) fn hold(&self, window: &Window, held: bool) -> Option<String> {
        let share = if held { RETURN_AT } else { HOLD_AT };
        if let Some(limit) = window.usd.filter(|limit| self.usd >= limit * share) {
            return Some(format!(
                "${:.2} of ${limit} per {} used",
                self.usd, window.span
            ));
        }
        if window.requests_estimate {
            return None;
        }
        let limit = window.requests?;
        (self.requests as f64 >= limit as f64 * share).then(|| {
            format!(
                "{} of {limit} requests per {} used",
                self.requests, window.span
            )
        })
    }
}

/// A window's usage over the given model groups. The 5-hour window sums the request log;
/// longer windows sum whole days of the gateway's daily totals (today and the days before).
fn used(
    client: &reqwest::blocking::Client,
    gateway: &str,
    key: &str,
    groups: &[String],
    span: &str,
    deadline: Instant,
) -> Result<Used, String> {
    let now = time::OffsetDateTime::now_utc();
    let days = match span {
        "5h" => {
            return logged(
                client,
                gateway,
                key,
                groups,
                now - time::Duration::hours(5),
                now,
                deadline,
            )
        }
        "day" => 1,
        "week" => 7,
        "month" => 30,
        other => {
            return Err(format!(
                "window span {other:?} is not 5h, day, week or month"
            ))
        }
    };
    let today = now.date();
    let from = today - time::Duration::days(days - 1);
    let activity = fetch_all_pages(
        client,
        gateway,
        key,
        &format!("/user/daily/activity?start_date={from}&end_date={today}"),
        deadline
            .checked_duration_since(Instant::now())
            .ok_or("gateway window deadline elapsed")?,
    )?;
    let mut used = Used::default();
    for day in activity
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for group in groups {
            if let Some(metrics) = day.pointer(&format!("/breakdown/model_groups/{group}/metrics"))
            {
                used.usd += metrics.get("spend").and_then(Value::as_f64).unwrap_or(0.0);
                used.requests += metrics
                    .get("successful_requests")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
            }
        }
    }
    Ok(used)
}

fn logged(
    client: &reqwest::blocking::Client,
    gateway: &str,
    key: &str,
    groups: &[String],
    from: time::OffsetDateTime,
    to: time::OffsetDateTime,
    deadline: Instant,
) -> Result<Used, String> {
    let stamp = |at: time::OffsetDateTime| {
        format!(
            "{}%20{:02}:{:02}:{:02}",
            at.date(),
            at.hour(),
            at.minute(),
            at.second()
        )
    };
    let mut used = Used::default();
    for group in groups {
        for page in 1u32.. {
            let rows = fetch(
                client,
                gateway,
                key,
                &format!(
                    "/spend/logs/v2?start_date={}&end_date={}&model_group={group}&page_size={LOG_PAGE}&page={page}",
                    stamp(from),
                    stamp(to)
                ),
                deadline.checked_duration_since(Instant::now()).ok_or("gateway window deadline elapsed")?,
            )?;
            for row in rows
                .get("data")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|row| row.get("status").and_then(Value::as_str) != Some("failure"))
            {
                used.usd += row.get("spend").and_then(Value::as_f64).unwrap_or(0.0);
                used.requests += 1;
            }
            let pages = rows.get("total_pages").and_then(Value::as_u64).unwrap_or(0);
            if u64::from(page) >= pages {
                break;
            }
        }
    }
    Ok(used)
}

/// The book plus each account's window usage and holds.
#[derive(Debug)]
pub(crate) struct Reading {
    pub book: Book,
    pub used: BTreeMap<String, Vec<(Window, Used)>>,
    pub holds: BTreeMap<String, String>,
    sources: sources::Collected,
    attribution: Option<Value>,
}

/// The last reading of a gateway, and the accounts held then (kept across a failed read).
struct Last {
    gateway: String,
    at: Instant,
    reading: Result<Arc<Reading>, String>,
    held: BTreeSet<String>,
}

static LAST: parking_lot::Mutex<Option<Last>> = parking_lot::Mutex::new(None);

/// Accounts a provider refused lately, with when and why. Process-wide, because a refusal is
/// the account's upstream state, not something one gateway reading saw.
static REFUSALS: parking_lot::Mutex<BTreeMap<String, (Instant, String)>> =
    parking_lot::Mutex::new(BTreeMap::new());

/// Holds the account of `lane` for [`REFUSAL_HOLD`] after its provider refused a request.
pub(crate) fn note_refusal(book: &Book, lane: &str, cause: &str) {
    if let Some(lane) = book.lanes.get(lane) {
        REFUSALS
            .lock()
            .insert(lane.account.clone(), (Instant::now(), cause.to_owned()));
    }
}

/// An account's live refusal cause; expired refusals are dropped here.
fn refusal(account: &str) -> Option<String> {
    let mut refusals = REFUSALS.lock();
    refusals.retain(|_, (at, _)| at.elapsed() < REFUSAL_HOLD);
    refusals.get(account).map(|(_, cause)| cause.clone())
}

/// The model book with its usage, read at most once a minute per gateway.
pub(crate) fn read_book(gateway: &str) -> Result<Arc<Reading>, String> {
    let held = match LAST.lock().as_ref().filter(|last| last.gateway == gateway) {
        Some(last) if last.at.elapsed() < READING_TTL => return last.reading.clone(),
        Some(last) => last.held.clone(),
        None => BTreeSet::new(),
    };
    let reading = read_gateway(gateway, &held).map(Arc::new);
    let held = match &reading {
        Ok(reading) => reading.holds.keys().cloned().collect(),
        Err(_) => held,
    };
    *LAST.lock() = Some(Last {
        gateway: gateway.to_owned(),
        at: Instant::now(),
        reading: reading.clone(),
        held,
    });
    reading
}

fn read_gateway(gateway: &str, held: &BTreeSet<String>) -> Result<Reading, String> {
    let key = gateway::key()?;
    let deadline = Instant::now() + GATEWAY_READING_TIMEOUT;
    let client =
        crate::http_pool::default_redirect().map_err(|error| format!("gateway client: {error}"))?;
    let mut book = Book::from_model_info(&fetch(
        client,
        gateway,
        &key,
        "/model/info",
        MODEL_INFO_TIMEOUT,
    )?)?;
    let family = local_family();
    let members = family.as_deref().unwrap_or_default();
    book.add_local_family(members);
    let (mut sources, attribution) = std::thread::scope(|scope| {
        let attribution = scope.spawn(|| super::spend::read_book_spend(gateway, &key, &book));
        let sources = sources::collect(&book);
        (
            sources,
            attribution
                .join()
                .unwrap_or_else(|_| Err("gateway attribution reader panicked".to_owned())),
        )
    });
    let attribution = match attribution {
        Ok(summary) => {
            sources
                .usages
                .extend(sources::gateway_usages(&book, &summary));
            if let Some(error) = summary.get("attribution_error").and_then(Value::as_str) {
                sources.errors.push(sources::SourceError {
                    account: None,
                    source: "gateway-attribution".to_owned(),
                    host: None,
                    message: error.to_owned(),
                });
            }
            Some(summary)
        }
        Err(message) => {
            sources.errors.push(sources::SourceError {
                account: None,
                source: "gateway-attribution".to_owned(),
                host: None,
                message,
            });
            None
        }
    };
    if let Err(message) = &family {
        sources.errors.push(sources::SourceError {
            account: None,
            source: "local-models".to_owned(),
            host: None,
            message: message.clone(),
        });
    }
    let mut usage_by_account = BTreeMap::new();
    let mut holds = BTreeMap::new();
    for (id, account) in &book.accounts {
        let groups = book.groups_of(id);
        // Every declared window with its gateway estimate; an unreadable estimate stays Err.
        let mut estimates: Vec<(&Window, Result<Used, String>)> = Vec::new();
        for window in &account.windows {
            let estimate = used(client, gateway, &key, &groups, &window.span, deadline);
            if let Err(error) = &estimate {
                sources.errors.push(sources::SourceError {
                    account: Some(id.clone()),
                    source: "gateway-estimate".to_owned(),
                    host: None,
                    message: format!("{} estimate is unreadable: {error}", window.span),
                });
            }
            estimates.push((window, estimate));
        }
        let usages: Vec<_> = sources
            .usages
            .iter()
            .filter(|row| row.account == *id)
            .collect();
        // Only the host-local readers' errors reach the hold decision; the
        // gateway-estimate errors pushed above surface as window holds and board errors.
        let errors: Vec<_> = sources
            .errors
            .iter()
            .filter(|error| {
                error.account.as_ref() == Some(id) && error.source != "gateway-estimate"
            })
            .collect();
        for hold in account_holds(account, &usages, &errors, &estimates, held.contains(id)) {
            holds.entry(id.clone()).or_insert(hold);
        }
        usage_by_account.insert(
            id.clone(),
            estimates
                .into_iter()
                .filter_map(|(window, estimate)| estimate.ok().map(|usage| (window.clone(), usage)))
                .collect(),
        );
    }
    for member in members {
        if let Some(hold) = &member.hold {
            holds.insert(member.lane(), hold.clone());
        }
    }
    Ok(Reading {
        book,
        used: usage_by_account,
        holds,
        sources,
        attribution,
    })
}

/// Why one account is held, strongest reason first: no key, its provider readings' own
/// limits, a failed provider read, then its declared windows' gateway estimates.
///
/// A failed provider read holds outright only while the gateway estimate does not cover
/// the declared windows (an unreadable window, or none declared); a covered account
/// holds on that estimate at the same [`HOLD_AT`]/[`RETURN_AT`] shares instead of
/// forever.
fn account_holds(
    account: &Account,
    usages: &[&sources::Usage],
    errors: &[&sources::SourceError],
    windows: &[(&Window, Result<Used, String>)],
    held: bool,
) -> Vec<String> {
    let mut holds = Vec::new();
    if let Some(cause) = refusal(&account.id) {
        holds.push(format!("refused upstream: {cause}"));
    }
    if !account.keyed {
        holds.push(format!(
            "no key: {} is not in sops",
            account.secret.as_deref().unwrap_or("its key")
        ));
    }
    holds.extend(usages.iter().filter_map(|row| row.hold(held)));
    // The estimate is usable when the account declared windows and every one reads.
    let covered = !windows.is_empty() && windows.iter().all(|(_, usage)| usage.is_ok());
    if !covered {
        holds.extend(
            errors
                .iter()
                .map(|error| format!("{} is unreadable: {}", error.source, error.message)),
        );
    }
    for (window, usage) in windows {
        // A provider's matching quota supersedes a local list-price estimate.
        // Keep unmatched declared windows (for example a request limit) in force.
        let authoritative = usages.iter().any(|row| {
            row.routing
                && !row.estimate
                && row.span.as_deref() == Some(window.span.as_str())
                && (window.requests.is_none() || window.requests_estimate || row.unit == "requests")
        });
        match usage {
            Ok(usage) => {
                if !authoritative {
                    holds.extend(usage.hold(window, held));
                }
            }
            Err(error) => {
                if !authoritative
                    && (window.usd.is_some()
                        || (window.requests.is_some() && !window.requests_estimate))
                {
                    holds.push(format!("its {} window is unreadable: {error}", window.span));
                }
            }
        }
    }
    holds
}

impl Reading {
    #[cfg(test)]
    pub(crate) fn test_reading(info: &Value) -> Self {
        Self {
            book: Book::from_model_info(info).expect("declared test model book"),
            used: BTreeMap::new(),
            holds: BTreeMap::new(),
            sources: sources::Collected::default(),
            attribution: None,
        }
    }

    /// Every declared class route must be an admitted launch, not just the lane selected now.
    pub(crate) fn validate_launches<'a>(
        &self,
        launches: impl Iterator<Item = &'a str>,
    ) -> Result<(), String> {
        self.book.validate_launches(launches)
    }

    /// The holds now: the reading's, plus any refusal noted since it was read.
    fn holds_now(&self) -> BTreeMap<String, String> {
        let mut holds = self.holds.clone();
        for account in self.book.accounts.keys() {
            if let Some(cause) = refusal(account) {
                holds.insert(account.clone(), format!("refused upstream: {cause}"));
            }
        }
        holds
    }

    /// The lane a class runs on now, for work with these needs.
    pub(crate) fn pick(&self, class: &str, needs: Needs) -> Result<String, String> {
        let order = self
            .book
            .class_lanes(class, &self.holds_now())
            .ok_or_else(|| format!("class {class} is not declared (gateway.classes)"))?;
        pick(class, &order, needs).map(|lane| lane.lane.clone())
    }

    /// Whether a lane can take work with these needs now; a lane the book does not declare cannot.
    pub(crate) fn admits(&self, lane: &str, needs: Needs) -> bool {
        self.book
            .lane_state(lane, &self.holds_now())
            .is_some_and(|lane| lane.refusal(needs).is_none())
    }

    /// Where a vehicle on `current` moves before its next turn: `None` stays. A lane the route
    /// did not put it on (`routed` false: launch or the owner's pick) stays while it has room; a
    /// routed one follows the class order.
    pub(crate) fn next_lane(
        &self,
        class: &str,
        current: &str,
        routed: bool,
        needs: Needs,
    ) -> Result<Option<String>, String> {
        if !routed && self.admits(current, needs) {
            return Ok(None);
        }
        let lane = self.pick(class, needs)?;
        Ok((lane != current).then_some(lane))
    }

    /// The board: every account with its lanes, windows and hold, and every class in order.
    pub(crate) fn board(&self) -> Value {
        let holds = self.holds_now();
        let accounts: Vec<Value> = self
            .book
            .accounts
            .values()
            .map(|account| {
                let lanes: Vec<&String> = self
                    .book
                    .lanes
                    .iter()
                    .filter(|(_, lane)| lane.account == account.id)
                    .map(|(name, _)| name)
                    .collect();
                let windows: Vec<Value> = account.windows.iter().map(|window| {
                        let used = self.used.get(&account.id)
                            .and_then(|windows| windows.iter().find(|(declared, _)| declared == window))
                            .map(|(_, usage)| usage);
                        json!({
                            "span": window.span,
                            "usd_limit": window.usd,
                            "usd_used": used.map(|used| (used.usd * 100.0).round() / 100.0),
                            "requests_limit": window.requests,
                            "requests_used": used.map(|used| used.requests),
                            "requests_estimate": window.requests_estimate,
                            "source": "gateway",
                            "estimate": true,
                        })
                    })
                    .collect();
                let held = holds.get(&account.id);
                json!({
                    "account": account.id,
                    "provider": account.provider,
                    "billing": account.billing,
                    "monthly_usd": account.monthly_usd,
                    "renews": account.renews,
                    "lanes": lanes,
                    "windows": windows,
                    "held": held,
                    "usages": self.sources.usages.iter().filter(|usage| usage.account == account.id).collect::<Vec<_>>(),
                    "source_errors": self.sources.errors.iter().filter(|error| error.account.as_ref() == Some(&account.id)).collect::<Vec<_>>(),
                })
            })
            .collect();
        let classes: Vec<Value> = self
            .book
            .classes
            .keys()
            .map(|class| {
                let order = self
                    .book
                    .class_lanes(class, &self.holds)
                    .unwrap_or_default();
                // The lane serving now, or null with the reason none can.
                let serving = self.pick(class, Needs::default());
                json!({
                    "class": class,
                    "order": order,
                    "serving": serving.as_ref().ok(),
                    "unavailable": serving.as_ref().err(),
                })
            })
            .collect();
        json!({
            "accounts": accounts,
            "classes": classes,
            "usages": self.sources.usages,
            "source_errors": self.sources.errors,
            "attribution": self.attribution,
            "note": format!(
                "Provider limits, resets and balances are authoritative where supplied; gateway windows and ccusage \
                 are local list-price estimates, not invoices. Subscription use is included; billed API dollars \
                 are separate. Sources overlap: do not add estimates to provider totals. An account is held at {:.0}% \
                 of a window and takes work again below {:.0}%. Provider sign-ins live with the authority's single \
                 auth holder; missing readings stay unknown.",
                HOLD_AT * 100.0,
                RETURN_AT * 100.0
            ),
        })
    }
}

pub(super) fn models_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    let handler = move |_scope: Scope, _arguments: Value| {
        let gateway = runtime
            .model_gateway()
            .ok_or_else(|| HostToolError::unavailable(TOOL, NO_GATEWAY))?;
        read_book(&gateway)
            .map(|reading| reading.board())
            .map_err(|error| HostToolError::unavailable(TOOL, error))
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Read models and plans".into(),
            description: "Every model plan and key (billing, monthly cost, renewal, how much of each usage \
                          window is used, whether it is held), its lanes, and the fast/standard/strong \
                          classes in order with the lane each runs on now."
                .into(),
            parameters: capability_parameters!("models.read"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}

/// A lane's standing in the gateway reading: outside the declared book, open, or held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaneStanding {
    Undeclared,
    Open,
    Held(String),
}

/// The standing of the account behind a bare lane name, from the same cached reading the board uses.
pub fn lane_standing(gateway: &str, lane: &str) -> Result<LaneStanding, String> {
    let reading = read_book(gateway)?;
    let Some(declared) = reading.book.lanes.get(lane) else {
        return Ok(LaneStanding::Undeclared);
    };
    Ok(match reading.holds_now().remove(&declared.account) {
        Some(reason) => LaneStanding::Held(reason),
        None => LaneStanding::Open,
    })
}

/// `odin models` over Huginn: the same board.
pub fn read_model_board(gateway: &str) -> Result<Value, String> {
    read_book(gateway).map(|reading| reading.board())
}

/// Validate a route declaration without reading usage, balances, or host-local OAuth stores.
///
/// Startup tolerates gateway connection failures, 5xx and non-JSON responses
/// within the reading deadline. A refused book or a 4xx fails immediately:
/// declaration and credential defects cannot be repaired by waiting.
pub fn validate_model_launches(gateway: &str, launches: &[String]) -> Result<(), String> {
    let key = gateway::key()?;
    let client =
        crate::http_pool::default_redirect().map_err(|error| format!("gateway client: {error}"))?;
    let deadline = Instant::now() + GATEWAY_READING_TIMEOUT;
    let info = loop {
        let timeout = MODEL_INFO_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
        match fetch(client, gateway, &key, "/model/info", timeout) {
            Ok(info) => break info,
            Err(error) if gateway_not_ready(&error) => {
                if Instant::now() + READINESS_RETRY_INTERVAL >= deadline {
                    return Err(error);
                }
                tracing::warn!(
                    "odin-hermes: the gateway is not answering yet, awaiting it: {error}"
                );
                std::thread::sleep(READINESS_RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    };
    Book::from_model_info(&info)?.validate_launches(launches.iter().map(String::as_str))
}

/// Whether a `/model/info` failure means LiteLLM is still coming up.
/// Unreachable, a 5xx, or a non-JSON body is readiness. A 4xx names its
/// status and is a credential or route defect.
fn gateway_not_ready(error: &str) -> bool {
    if error.contains("unreadable JSON") || error.contains("unreachable") {
        return true;
    }
    error
        .split("answered ")
        .nth(1)
        .and_then(|rest| {
            rest.split(|character: char| !character.is_ascii_digit())
                .next()
        })
        .is_some_and(|code| code.starts_with('5'))
}

/// A rendered gateway config (`litellm.yaml`) as LiteLLM serves it: the
/// `model_list` entries are the `/model/info` document.
#[derive(Deserialize)]
struct RenderedGateway {
    #[serde(default)]
    model_list: Vec<RenderedModel>,
}

#[derive(Deserialize)]
struct RenderedModel {
    model_name: String,
    #[serde(default)]
    model_info: Option<Value>,
}

/// Validate the rendered gateway config through the production book reader,
/// with no gateway contact: the deploy's candidate check parses the exact
/// config the gateway will serve before anything publishes, so a broken
/// render (a lane whose account lost `windows`, a dropped lane a launch
/// names) is refused before the switch, not by the daemon after it.
pub fn validate_rendered_gateway(config: &str, launches: &[String]) -> Result<(), String> {
    let rendered: RenderedGateway = serde_yaml::from_str(config)
        .map_err(|error| format!("the rendered gateway config is unreadable: {error}"))?;
    let data: Vec<Value> = rendered
        .model_list
        .into_iter()
        .map(|model| {
            json!({
                "model_name": model.model_name,
                "model_info": model.model_info.unwrap_or_else(|| json!({})),
            })
        })
        .collect();
    let book = Book::from_model_info(&json!({"data": data}))
        .map_err(|error| format!("the rendered gateway config is invalid: {error}"))?;
    for launch in launches {
        let served = book.lanes.contains_key(launch)
            || book
                .classes
                .get(launch)
                .is_some_and(|order| !order.is_empty());
        if !served {
            return Err(format!(
                "the rendered gateway serves no lane or class {launch}"
            ));
        }
    }
    for (class, order) in &book.classes {
        for lane in order {
            if !book.lanes.contains_key(lane) {
                return Err(format!("class {class} names undeclared lane {lane}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::gateway::KEY_ENV;
    use super::*;

    /// LiteLLM 1.97 `/model/info` with the generated `model_info.odin`.
    fn model_info() -> Value {
        let goat = json!({"id": "commandcode-goat", "provider": "Command Code", "billing": "subscription",
            "monthly_usd": 10, "renews": null, "secret": "COMMANDCODE_API_KEY", "keyed": true,
            "windows": [{"span": "5h", "usd": 14, "requests": null}]});
        let supergrok = json!({"id": "supergrok", "provider": "SuperGrok (xAI)", "billing": "subscription",
            "monthly_usd": null, "renews": null, "secret": null, "keyed": true, "windows": []});
        let deepseek = json!({"id": "deepseek", "provider": "DeepSeek", "billing": "api",
            "monthly_usd": null, "renews": null, "secret": "DEEPSEEK_API_KEY", "keyed": true, "windows": []});
        json!({"data": [
            {"model_name": "goat-flash", "model_info": {"odin": {"account": goat, "vision": false,
                "context_window": 1048576}}},
            {"model_name": "grok", "model_info": {"odin": {"account": supergrok, "vision": true,
                "context_window": 500000}}},
            {"model_name": "deepseek-chat", "model_info": {"odin": {"account": deepseek, "vision": false,
                "context_window": 1048576}}},
            {"model_name": "fast", "model_info": {"odin": {"account": goat, "vision": false,
                "context_window": 1048576,
                "class": {"name": "fast", "order": ["goat-flash", "grok"]}}}},
            {"model_name": "wemm-embedding", "model_info": {}},
        ]})
    }

    #[test]
    fn the_book_reads_accounts_lanes_and_classes() {
        let book = Book::from_model_info(&model_info()).unwrap();
        assert_eq!(book.classes["fast"], ["goat-flash", "grok"]);
        assert_eq!(book.lanes.len(), 3);
        assert_eq!(book.billing("fast"), Some("subscription"));
        assert_eq!(book.billing("deepseek-chat"), Some("api"));
        assert_eq!(book.billing("wemm-embedding"), None);
        assert_eq!(book.groups_of("commandcode-goat"), ["goat-flash", "fast"]);
    }

    #[test]
    fn a_spent_window_moves_the_class_to_its_next_lane() {
        let book = Book::from_model_info(&model_info()).unwrap();
        let window = book.accounts["commandcode-goat"].windows[0].clone();
        let spent = Used {
            usd: 12.8,
            requests: 900,
        };
        let hold = spent.hold(&window, false).unwrap();
        assert_eq!(hold, "$12.80 of $14 per 5h used");
        let easing = Used {
            usd: 11.2,
            requests: 9,
        };
        assert_eq!(easing.hold(&window, false), None);
        assert_eq!(
            easing.hold(&window, true).as_deref(),
            Some("$11.20 of $14 per 5h used"),
            "a held account stays held until below 75%"
        );
        assert_eq!(
            Used {
                usd: 3.0,
                requests: 9
            }
            .hold(&window, true),
            None
        );
        let reading = Reading {
            book,
            used: BTreeMap::new(),
            holds: BTreeMap::from([("commandcode-goat".to_owned(), hold)]),
            sources: sources::Collected::default(),
            attribution: None,
        };
        assert_eq!(reading.pick("fast", Needs::default()).unwrap(), "grok");
        let next = |current: &str, routed: bool| {
            reading
                .next_lane("fast", current, routed, Needs::default())
                .unwrap()
        };
        assert_eq!(
            next("goat-flash", false).as_deref(),
            Some("grok"),
            "held: moves on"
        );
        assert_eq!(
            next("deepseek-chat", false),
            None,
            "the owner's pick with room stays"
        );
        assert_eq!(
            next("grok", true),
            None,
            "already on the first lane with room"
        );
        let board = reading.board();
        assert_eq!(board["classes"][0]["serving"], "grok");
        let free = Reading {
            holds: BTreeMap::new(),
            ..reading
        };
        assert_eq!(
            free.next_lane("fast", "grok", true, Needs::default())
                .unwrap()
                .as_deref(),
            Some("goat-flash"),
            "a routed vehicle goes back to the first lane once it has room"
        );
        assert_eq!(
            board["classes"][0]["order"][0]["held"],
            "$12.80 of $14 per 5h used"
        );
    }

    fn declared_account(keyed: bool, windows: Vec<Window>) -> Account {
        Account {
            id: "commandcode-goat".to_owned(),
            provider: "Command Code".to_owned(),
            billing: "subscription".to_owned(),
            monthly_usd: Some(10.0),
            renews: None,
            secret: Some("COMMANDCODE_API_KEY".to_owned()),
            keyed,
            windows,
        }
    }

    fn five_hour_window() -> Window {
        Window {
            span: "5h".to_owned(),
            usd: Some(14.0),
            requests: None,
            requests_estimate: false,
        }
    }

    fn unreadable_reading() -> sources::SourceError {
        sources::SourceError {
            account: Some("commandcode-goat".to_owned()),
            source: "omp".to_owned(),
            host: Some("mini".to_owned()),
            message: "usage command exited 1".to_owned(),
        }
    }

    #[test]
    fn an_unreadable_reading_holds_on_a_covering_gateway_estimate() {
        let account = declared_account(true, vec![five_hour_window()]);
        let window = &account.windows[0];
        let holds = |usd: f64, held: bool| {
            account_holds(
                &account,
                &[],
                &[&unreadable_reading()],
                &[(window, Ok(Used { usd, requests: 9 }))],
                held,
            )
        };
        assert_eq!(
            holds(12.8, false),
            ["$12.80 of $14 per 5h used"],
            "a covered account holds on the estimate at 90%, not on the failed read"
        );
        assert!(
            holds(11.2, false).is_empty(),
            "an unheld account below 90% keeps serving while its reading is unavailable"
        );
        assert_eq!(
            holds(11.2, true),
            ["$11.20 of $14 per 5h used"],
            "a held account resumes only below 75%"
        );
        assert!(
            holds(3.0, true).is_empty(),
            "below 75% the lane takes work again"
        );
    }

    #[test]
    fn a_keyless_account_stays_held_even_with_a_covering_estimate() {
        let window = five_hour_window();
        let account = declared_account(false, vec![window.clone()]);
        assert_eq!(
            account_holds(
                &account,
                &[],
                &[&unreadable_reading()],
                &[(&window, Ok(Used::default()))],
                false
            ),
            ["no key: COMMANDCODE_API_KEY is not in sops"],
            "a keyless account holds regardless of the estimate"
        );
    }

    /// A `/model/info` document whose classes cover every launch the daemon
    /// validates: fast, standard and strong with declared orders.
    fn launchable_model_info() -> Value {
        let goat = json!({"id": "commandcode-goat", "provider": "Command Code",
            "billing": "subscription", "monthly_usd": 10, "renews": null,
            "secret": "COMMANDCODE_API_KEY", "keyed": true,
            "windows": [{"span": "5h", "usd": 14, "requests": null}]});
        let grok = json!({"id": "supergrok", "provider": "SuperGrok (xAI)", "billing": "subscription",
            "monthly_usd": null, "renews": null, "secret": null, "keyed": true, "windows": []});
        let deepseek = json!({"id": "deepseek", "provider": "DeepSeek", "billing": "api",
            "monthly_usd": null, "renews": null, "secret": "DEEPSEEK_API_KEY", "keyed": true,
            "windows": []});
        let lane = |name: &str, account: &Value| {
            json!({"model_name": name, "model_info": {"odin": {"account": account,
                "vision": false, "context_window": 1048576}}})
        };
        let class = |name: &str, account: &Value, order: &[&str]| {
            json!({"model_name": name, "model_info": {"odin": {"account": account,
                "vision": false, "context_window": 1048576,
                "class": {"name": name, "order": order}}}})
        };
        json!({"data": [
            lane("goat-flash", &goat),
            lane("grok", &grok),
            lane("deepseek-chat", &deepseek),
            class("fast", &goat, &["goat-flash", "grok"]),
            class("standard", &deepseek, &["deepseek-chat"]),
            class("strong", &grok, &["grok"]),
        ]})
    }

    /// A loopback gateway answering `/model/info` with the queued responses
    /// in order, one connection each; it counts the requests it answered.
    fn sequencing_gateway(
        responses: Vec<(u16, String)>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let answered = std::sync::Arc::new(AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&answered);
        std::thread::spawn(move || {
            let mut responses = std::collections::VecDeque::from(responses);
            // A connection the client drops mid-request (a timed-out attempt under load)
            // does not use up an answer.
            while let Some((status, body)) = responses.pop_front() {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let mut request = Vec::new();
                let mut buffer = [0_u8; 8192];
                let mut dropped = false;
                loop {
                    let Ok(read) = stream.read(&mut buffer) else {
                        dropped = true;
                        break;
                    };
                    if read == 0 {
                        dropped = request.is_empty();
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if let Some((head, body)) =
                        String::from_utf8_lossy(&request).split_once("\r\n\r\n")
                    {
                        let length = head
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(str::to_owned)
                            })
                            .and_then(|length| length.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if body.len() >= length {
                            break;
                        }
                    }
                }
                if dropped {
                    responses.push_front((status, body));
                    continue;
                }
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                // Counted before the client can see the answer.
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{address}"), answered)
    }

    #[test]
    fn startup_awaits_the_gateways_first_model_info_answer() {
        std::env::set_var(KEY_ENV, "test-key");
        let (url, answered) = sequencing_gateway(vec![
            (503, r#"{"detail":"starting up"}"#.to_owned()),
            (503, r#"{"detail":"starting up"}"#.to_owned()),
            (200, launchable_model_info().to_string()),
        ]);
        let launches = vec![
            "goat-flash".to_owned(),
            "grok".to_owned(),
            "deepseek-chat".to_owned(),
        ];
        validate_model_launches(&url, &launches)
            .expect("the gateway answered within the reading bound");
        assert!(
            answered.load(std::sync::atomic::Ordering::SeqCst) >= 3,
            "the two refused answers were awaited, not failed on"
        );
    }

    /// The `models_read` tool serves the declared plans, their lanes and the class order from the gateway's book.
    #[test]
    fn models_read_serves_the_plans_lanes_and_class_order_of_the_gateway() {
        use std::io::{Read, Write};
        std::env::set_var(KEY_ENV, "test-key");
        let root = tempfile::tempdir().expect("state");
        let usage = root.path().join("model-usage.json");
        std::fs::write(&usage, r#"{"sources": []}"#).unwrap();
        std::env::set_var("ODIN_MODEL_USAGE_CONFIG", &usage);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut request = [0_u8; 8192];
                let read = stream.read(&mut request).unwrap_or(0);
                let head = String::from_utf8_lossy(&request[..read]);
                let (status, body) = if head.starts_with("GET /model/info") {
                    ("200 OK", model_info().to_string())
                } else {
                    ("404 Not Found", "{}".to_owned())
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let settings = crate::config::HermesSettings::new(
            root.path().join("state"),
            None,
            None,
            Vec::new(),
        )
        .expect("hermes settings");
        let ledgers = crate::runtime::HermesLedgers {
            conversation: odin_ledger::Ledger::open_in_memory().expect("conversation ledger"),
            adapter: std::sync::Arc::new(parking_lot::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("adapter ledger"),
            )),
            purchase: std::sync::Arc::new(std::sync::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("purchase ledger"),
            )),
        };
        let runtime = crate::runtime::HermesRuntime::open(
            settings,
            ledgers,
            &BTreeMap::new(),
            None,
            8_192,
            BTreeMap::new(),
            None,
        )
        .expect("hermes runtime");
        runtime.set_model_gateway(url);
        let mut tools = Vec::new();
        models_tools(&runtime, &mut tools);
        let board = tools
            .pop()
            .expect("models_read tool")
            .invoke(odin_omp::host_tools::HostInvocation {
                scope: Scope::default(),
                arguments: json!({}),
            })
            .expect("the board");
        let goat = board["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|account| account["account"] == "commandcode-goat")
            .expect("the declared plan is on the board");
        assert_eq!(goat["billing"], "subscription");
        assert_eq!(goat["lanes"], json!(["goat-flash"]));
        assert_eq!(goat["windows"][0]["span"], "5h");
        let fast = board["classes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|class| class["class"] == "fast")
            .expect("the fast class");
        let order: Vec<&Value> = fast["order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|lane| &lane["lane"])
            .collect();
        assert_eq!(order, ["goat-flash", "grok"]);
        assert!(
            fast["order"][0]["held"]
                .as_str()
                .unwrap()
                .contains("unreadable"),
            "a window the gateway cannot read holds its lane: {fast}"
        );
    }

    #[test]
    fn a_refused_book_fails_at_once_without_awaiting() {
        std::env::set_var(KEY_ENV, "test-key");
        let mut refused = launchable_model_info();
        refused["data"][0]["model_info"]["odin"]["account"]
            .as_object_mut()
            .expect("account object")
            .remove("windows");
        let (url, answered) = sequencing_gateway(vec![(200, refused.to_string())]);
        let launches = vec![
            "goat-flash".to_owned(),
            "grok".to_owned(),
            "deepseek-chat".to_owned(),
        ];
        let error = validate_model_launches(&url, &launches)
            .expect_err("a lane without windows refuses the book");
        assert!(
            error.contains("goat-flash") && error.contains("missing field `windows`"),
            "the refusal names the lane and the field: {error}"
        );
        assert_eq!(
            answered.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a refused book is a declaration defect, not readiness"
        );
    }

    /// The declared account as the renderer writes it into `model_info`.
    fn goat_account() -> Value {
        json!({"id": "commandcode-goat", "provider": "Command Code",
            "billing": "subscription", "monthly_usd": 10, "renews": null,
            "secret": "COMMANDCODE_API_KEY", "keyed": true,
            "windows": [{"span": "5h", "usd": 14, "requests": null}]})
    }

    /// The rendered `litellm.yaml` shape the gateway renderer emits — a
    /// model_list whose entries carry the `model_info.odin` block LiteLLM
    /// serves back on `/model/info` — serialized as the renderer writes it.
    fn rendered_gateway(account: Value) -> String {
        let config = json!({
            "model_list": [{
                "model_name": "goat-flash",
                "litellm_params": {
                    "model": "commandcode/goat-flash",
                    "api_key": "os.environ/GOAT_API_KEY",
                },
                "model_info": {"odin": {
                    "account": account,
                    "tier": "everyday",
                    "vision": false,
                    "context_window": 1048576,
                }},
            }],
            "router_settings": {"fallbacks": []},
            "general_settings": {"master_key": "os.environ/LITELLM_MASTER_KEY"},
        });
        serde_yaml::to_string(&config).expect("serialize the rendered gateway")
    }

    #[test]
    fn a_rendered_gateway_config_parses_through_the_production_book() {
        let config = rendered_gateway(goat_account());
        validate_rendered_gateway(&config, &["goat-flash".to_owned()])
            .expect("the rendered config carries the declared account windows");
    }

    /// `local-models scan`'s list document: a chat model, a vision model and an embedding.
    fn local_list() -> Vec<LocalModel> {
        let list: LocalList = serde_json::from_value(json!({
            "version": 1,
            "scanned": "2026-10-30T01:00:00Z",
            "root": "/models",
            "models": [
                {"id": "lfm", "kind": "chat", "file": "lfm.gguf", "context": 128000},
                {"id": "qwen-vl", "kind": "vision", "file": "qwen-vl.gguf", "context": 65536},
                {"id": "bge", "kind": "embedding", "file": "bge.gguf", "context": null},
            ],
        }))
        .unwrap();
        list.models
    }

    #[test]
    fn a_family_card_expands_from_the_local_list() {
        let members = family_members(local_list(), None);
        assert!(
            members.iter().all(|member| member.hold.is_none()),
            "a listed model loads on demand"
        );
        let mut book = Book::from_model_info(&model_info()).unwrap();
        book.add_local_family(&members);
        assert_eq!(book.lanes["local/lfm"].context_window, 128000);
        assert!(book.lanes["local/qwen-vl"].vision);
        assert_eq!(book.billing("local/lfm"), Some("local"));
        assert!(
            !book.lanes.contains_key("local/bge"),
            "embedding is not a chat lane"
        );
    }

    #[test]
    fn kreate_mode_holds_every_local_member() {
        let since = "the local models are off: kreate mode since 2026-10-30T01:00:00Z";
        let members = family_members(local_list(), Some(since));
        assert_eq!(members.len(), 2);
        assert!(members
            .iter()
            .all(|member| member.hold.as_deref() == Some(since)));
    }
}
