//! The model catalog `/model` shows. The live list is the authority user's
//! `omp models --json` (every provider a sign-in or key exposes), cached ten
//! minutes. It joins the dotfiles lane allowlist (`[models]` in odind.toml):
//! a lane with `seats` may be run, everything else is named with the reason.
//! If `omp` fails, the note is its first stderr line and the declared seat
//! lanes still show.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use odin_domain::huginn::{self as live, GATEWAY_PROVIDER};
use odin_huginn::OdindModelLaneConfig;
use serde::Deserialize;

const CACHE_FOR: Duration = Duration::from_secs(10 * 60);
const RUN_BOUND: Duration = Duration::from_secs(20);
/// How often the listing child is checked for exit.
const RUN_POLL: Duration = Duration::from_millis(50);

pub(super) struct ModelCatalog {
    omp: PathBuf,
    lanes: BTreeMap<String, OdindModelLaneConfig>,
    family: Option<odin_registry::ModelCardToml>,
    cache: std::sync::Mutex<Option<(Instant, Vec<LiveModel>)>>,
}

impl ModelCatalog {
    pub(super) fn new(
        omp: PathBuf,
        lanes: BTreeMap<String, OdindModelLaneConfig>,
        family: Option<odin_registry::ModelCardToml>,
    ) -> Self {
        Self {
            omp,
            lanes,
            family,
            cache: std::sync::Mutex::new(None),
        }
    }

    pub(super) async fn read(&self) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let (live_rows, mut note) = match self.live_rows().await {
            Ok(rows) => (rows, String::new()),
            Err(error) => (Vec::new(), error),
        };
        let members = match odin_hermes::runtime::local_family() {
            Ok(members) => members,
            Err(error) => {
                if !note.is_empty() {
                    note.push_str("; ");
                }
                note.push_str(&error);
                Vec::new()
            }
        };
        let mut view = join(&self.lanes, &live_rows, note);
        for row in family_rows(self.family.as_ref(), &members) {
            if !view
                .rows
                .iter()
                .any(|existing| existing.selector == row.selector)
            {
                view.rows.push(row);
            }
        }
        view.rows
            .sort_by(|left, right| left.selector.cmp(&right.selector));
        Ok(live::HuginnResponse::ModelCatalog(view))
    }

    async fn live_rows(&self) -> Result<Vec<LiveModel>, String> {
        if let Some(cached) = self.cache.lock().expect("catalog cache").as_ref() {
            if cached.0.elapsed() < CACHE_FOR {
                return Ok(cached.1.clone());
            }
        }
        let omp = self.omp.clone();
        let parsed = tokio::task::spawn_blocking(move || run_omp(&omp))
            .await
            .map_err(|error| format!("omp models --json: {error}"))??;
        *self.cache.lock().expect("catalog cache") = Some((Instant::now(), parsed.clone()));
        Ok(parsed)
    }
}

fn run_omp(omp: &Path) -> Result<Vec<LiveModel>, String> {
    let mut child = Command::new(omp)
        .args(["models", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not run {}: {error}", omp.display()))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut pipe) = stdout {
            let _ = std::io::Read::read_to_string(&mut pipe, &mut buf);
        }
        buf
    });
    let err = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut pipe) = stderr {
            let _ = std::io::Read::read_to_string(&mut pipe, &mut buf);
        }
        buf
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > RUN_BOUND => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("omp models --json timed out".to_owned());
            }
            Ok(None) => std::thread::sleep(RUN_POLL),
            Err(error) => return Err(format!("omp models --json: {error}")),
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    if !status.success() {
        return Err(
            first_line(&stderr).unwrap_or_else(|| format!("omp models --json exited {status}"))
        );
    }
    parse_omp(&stdout)
}

fn first_line(text: &str) -> Option<String> {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_owned())
}

/// Joins one `omp models --json` document to the allowlist. Declared seat
/// lanes always appear, so a seat can still switch when the live list is
/// missing a host lane (kubert-mini) or `omp` failed.
fn join(
    lanes: &BTreeMap<String, OdindModelLaneConfig>,
    live_rows: &[LiveModel],
    note: String,
) -> live::ModelCatalogView {
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (name, lane) in lanes {
        if !lane.seats {
            continue;
        }
        let selector = format!("{GATEWAY_PROVIDER}/{name}");
        seen.insert(selector.clone());
        rows.push(lane_row(&selector, lane, true, String::new()));
    }
    for model in live_rows {
        if !seen.insert(model.selector.clone()) {
            continue;
        }
        let lane = (model.provider == GATEWAY_PROVIDER)
            .then(|| lanes.get(&model.id))
            .flatten();
        let (allowed, reason) = match lane {
            Some(lane) if lane.seats => (true, String::new()),
            Some(_) => (false, "not open to seats".to_owned()),
            None if model.provider == GATEWAY_PROVIDER => {
                (false, "not a declared model lane".to_owned())
            }
            None => (false, "no gateway lane declared".to_owned()),
        };
        rows.push(match lane {
            Some(lane) => lane_row(&model.selector, lane, allowed, reason),
            None => live::ModelCatalogRow {
                selector: model.selector.clone(),
                name: model.name.clone(),
                strengths: String::new(),
                tier: String::new(),
                seat_allowed: false,
                reason,
                context_window: model.context_window,
                input_per_million: usd(model.cost.input),
                output_per_million: usd(model.cost.output),
                billing: String::new(),
            },
        });
    }
    rows.sort_by(|left, right| left.selector.cmp(&right.selector));
    live::ModelCatalogView { note, rows }
}

/// The local family card's facts for each member on the local list. A member is seat-open
/// when the card is and mini holds nothing against it; its reason is the hold.
pub(super) fn family_card(
    registry: &[odin_registry::RegistryObject],
) -> Option<odin_registry::ModelCardToml> {
    registry.iter().find_map(|object| match &object.config {
        odin_registry::ObjectConfig::Model(card) if card.family => Some((**card).clone()),
        _ => None,
    })
}

fn family_rows(
    card: Option<&odin_registry::ModelCardToml>,
    members: &[odin_hermes::runtime::LocalMember],
) -> Vec<live::ModelCatalogRow> {
    let Some(card) = card else {
        return Vec::new();
    };
    members
        .iter()
        .map(|member| {
            let reason = match (&member.hold, card.seats) {
                (Some(hold), _) => hold.clone(),
                (None, false) => "not open to seats".to_owned(),
                (None, true) => String::new(),
            };
            live::ModelCatalogRow {
                selector: format!("{GATEWAY_PROVIDER}/{}", member.lane()),
                name: format!("{} (local)", member.id),
                strengths: card.strengths.clone(),
                tier: card.tier.clone().unwrap_or_default(),
                seat_allowed: card.seats && member.hold.is_none(),
                reason,
                context_window: member.context,
                input_per_million: "0".to_owned(),
                output_per_million: "0".to_owned(),
                billing: "local".to_owned(),
            }
        })
        .collect()
}

fn lane_row(
    selector: &str,
    lane: &OdindModelLaneConfig,
    seat_allowed: bool,
    reason: String,
) -> live::ModelCatalogRow {
    live::ModelCatalogRow {
        selector: selector.to_owned(),
        name: lane.display_name.clone(),
        strengths: lane.strengths.clone(),
        tier: lane.tier.clone().unwrap_or_default(),
        seat_allowed,
        reason,
        context_window: lane.context_window,
        input_per_million: lane.cost.input.clone(),
        output_per_million: lane.cost.output.clone(),
        billing: lane.billing.clone(),
    }
}

fn usd(value: f64) -> String {
    if value.fract() == 0.0 && value < u64::MAX as f64 {
        format!("{}", value as u64)
    } else {
        format!("{value}")
    }
}

#[derive(Clone, Deserialize)]
struct LiveList {
    models: Vec<LiveModel>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveModel {
    provider: String,
    id: String,
    selector: String,
    name: String,
    #[serde(default)]
    context_window: u64,
    #[serde(default)]
    cost: LiveCost,
}

#[derive(Clone, Default, Deserialize)]
struct LiveCost {
    #[serde(default)]
    input: f64,
    #[serde(default)]
    output: f64,
}

fn parse_omp(text: &str) -> Result<Vec<LiveModel>, String> {
    serde_json::from_str::<LiveList>(text)
        .map(|list| list.models)
        .map_err(|error| format!("omp models --json: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_huginn::OdindModelCost;

    /// Three rows from a live `omp models --json` on pc (2026-10-20): one seat
    /// lane, one declared lane seats may not run, and one signed-in model with
    /// no lane.
    const EXCERPT: &str = r#"{"models":[
      {"provider":"gateway","kind":"chat","id":"grok","selector":"gateway/grok","name":"Grok 4.7 · SuperGrok (xAI OAuth)","contextWindow":500000,"maxTokens":128000,"reasoning":true,"thinking":["minimal","low","medium","high","xhigh"],"input":["text","image"],"cost":{"cacheRead":0.5,"cacheWrite":0,"input":2,"output":6},"pricingStatus":"fixed"},
      {"provider":"gateway","kind":"chat","id":"overflow","selector":"gateway/overflow","name":"OpenRouter Auto · API overflow","contextWindow":2000000,"maxTokens":30000,"reasoning":true,"thinking":["minimal","low","medium","high","xhigh"],"input":["text"],"cost":{"cacheRead":0,"cacheWrite":0,"input":0,"output":0},"pricingStatus":"unknown"},
      {"provider":"openai-codex","kind":"chat","id":"gpt-6-sol","selector":"openai-codex/gpt-6-sol","name":"GPT-6-Sol","contextWindow":272000,"maxTokens":128000,"reasoning":true,"thinking":["low","medium","high","xhigh","max"],"input":["text","image"],"cost":{"input":2,"output":10,"cacheRead":0.2,"cacheWrite":0},"pricingStatus":"fixed"}
    ]}"#;

    fn lane(seats: bool, name: &str) -> OdindModelLaneConfig {
        OdindModelLaneConfig {
            seats,
            strengths: format!("{name} lane"),
            tier: None,
            display_name: name.to_owned(),
            context_window: 500_000,
            cost: OdindModelCost {
                input: "2".to_owned(),
                output: "6".to_owned(),
            },
            billing: "subscription".to_owned(),
        }
    }

    #[test]
    fn a_real_omp_excerpt_joins_seat_lanes() {
        let live_rows = parse_omp(EXCERPT).expect("excerpt parses");
        let mut grok = lane(true, "Grok 4.7");
        grok.tier = Some("frontier".to_owned());
        let lanes = BTreeMap::from([
            ("grok".to_owned(), grok),
            ("overflow".to_owned(), lane(false, "OpenRouter Auto")),
            ("kubert-mini".to_owned(), lane(true, "Qwen3.6")),
        ]);
        let view = join(&lanes, &live_rows, String::new());
        let row = |selector: &str| {
            view.rows
                .iter()
                .find(|row| row.selector == selector)
                .unwrap_or_else(|| panic!("{selector} missing"))
        };
        assert!(row("gateway/grok").seat_allowed, "grok is a seat lane");
        assert_eq!(row("gateway/grok").strengths, "Grok 4.7 lane");
        assert_eq!(row("gateway/grok").tier, "frontier");
        assert!(!row("gateway/overflow").seat_allowed);
        assert!(
            row("gateway/overflow").reason.contains("not open to seats"),
            "{}",
            row("gateway/overflow").reason
        );
        assert!(!row("openai-codex/gpt-6-sol").seat_allowed);
        assert!(
            row("openai-codex/gpt-6-sol")
                .reason
                .contains("no gateway lane"),
            "{}",
            row("openai-codex/gpt-6-sol").reason
        );
        assert!(
            row("gateway/kubert-mini").seat_allowed,
            "a seat lane missing from the live list still shows"
        );
    }
}
