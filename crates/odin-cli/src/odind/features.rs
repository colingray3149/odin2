//! The Capabilities evaluator: one row per enabled capability (its named tests read from the deployed
//! gate results, its probes live), then one row per service (probes only), as one `Status/features`
//! object in the read model. Armed beside the spend pump. Evaluations run on startup, on every
//! registry revision, every five minutes and on a [`FeatureRefresh`] request.

#[path = "features/status.rs"]
mod status;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use odin_cli::feature_probe::{probe, ProbeResult, ProbeState};
use odin_domain::huginn as live;
use odin_huginn::NodePosture;
use odin_registry::schema::Probe;
use odin_registry::{ObjectConfig, RegistryKind, Snapshot, SnapshotHandle, SnapshotStore};
use serde::Deserialize;
use serde_json::{json, Value};
use status::{capability_status, service_status, CheckResult, Status};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::process::Command;
use tokio::sync::{watch, Notify};

/// Bound on one host probe, one HTTP check or one model reading.
const PROBE_BOUND: Duration = Duration::from_secs(5);
/// Re-evaluation cadence when nothing else asks for one.
const EVALUATE_INTERVAL: Duration = Duration::from_secs(5 * 60);
const STATUS_ID: &str = "features";
/// The group a service row sits under, and the group of a capability with no toolset.
const SERVICES_AREA: &str = "services";
const NO_TOOLSET_AREA: &str = "other";

/// Refresh plumbing for the features request, kept on the Huginn request port. `request` asks
/// the pump to evaluate now; `evaluated` changes after each finished evaluation. The port reads
/// them to answer `FeaturesRefresh`.
pub(crate) struct FeatureRefresh {
    pub(crate) request: Arc<Notify>,
    pub(crate) evaluated: watch::Receiver<Evaluation>,
}

/// How many evaluations have finished, and why the last one failed to publish.
#[derive(Clone, Default)]
pub(crate) struct Evaluation {
    count: u64,
    failure: Option<String>,
}

/// The pump's end of the refresh pair.
pub(super) struct FeatureTrigger {
    request: Arc<Notify>,
    evaluated: watch::Sender<Evaluation>,
}

/// One request pair: the port keeps `FeatureRefresh`, the pump owns `FeatureTrigger`.
pub(crate) fn refresh_pair() -> (FeatureRefresh, FeatureTrigger) {
    let request = Arc::new(Notify::new());
    let (evaluated, receiver) = watch::channel(Evaluation::default());
    (
        FeatureRefresh {
            request: Arc::clone(&request),
            evaluated: receiver,
        },
        FeatureTrigger { request, evaluated },
    )
}

/// The inputs one evaluation reads: the pinned registry, the deployed gate evidence, and the
/// hosts, SSH executable and model gateway the probes use.
pub(super) struct FeatureSources {
    pub(super) snapshot: Arc<SnapshotHandle>,
    pub(super) registry_snapshot: PathBuf,
    pub(super) state_root: PathBuf,
    pub(super) ssh: PathBuf,
    pub(super) gateway: Option<String>,
    pub(super) local_node: String,
}

/// `state_root/tested.json`, written by deploy: the gate's record for the deployed commit. Every
/// field may be absent.
#[derive(Deserialize)]
struct Tested {
    sha: Option<String>,
    at: Option<String>,
    /// `"<binary-id> <test-name>"` to pass, fail or skip, the key the capabilities' `tests` name.
    #[serde(default)]
    tests: BTreeMap<String, String>,
}

/// One row to evaluate: an enabled capability with its named tests and probes, or a service with
/// probes alone.
struct Row {
    id: String,
    title: String,
    area: String,
    service: bool,
    tests: Vec<String>,
    probes: Vec<String>,
}

/// How long a `FeaturesRefresh` request waits for the evaluation it woke.
const REFRESH_BOUND: Duration = Duration::from_secs(30);

/// Answers `FeaturesRefresh`: wakes the pump and waits for the next finished evaluation. Without
/// a refresh pair this node does not evaluate features (a follower).
pub(crate) async fn refresh(
    refresh: Option<&FeatureRefresh>,
) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
    let Some(refresh) = refresh else {
        return Err(live::HuginnProtocolError::unavailable(
            "featuresUnavailable",
            "features are evaluated only on the authority",
        ));
    };
    let mut evaluated = refresh.evaluated.clone();
    // Mark the current revision seen, so the wait ends only on an evaluation finished after this request.
    evaluated.borrow_and_update();
    refresh.request.notify_one();
    match tokio::time::timeout(REFRESH_BOUND, evaluated.changed()).await {
        Ok(Ok(())) => {
            let evaluation = evaluated.borrow().clone();
            match evaluation.failure {
                Some(failure) => Err(live::HuginnProtocolError::unavailable(
                    "featuresEvaluationFailed",
                    format!("the features evaluation failed: {failure}"),
                )),
                None => Ok(live::HuginnResponse::FeaturesRefreshed {
                    revision: evaluation.count,
                }),
            }
        }
        Ok(Err(_)) => Err(live::HuginnProtocolError::unavailable(
            "featuresUnavailable",
            "the features pump has stopped",
        )),
        Err(_) => Err(live::HuginnProtocolError::unavailable(
            "featuresTimeout",
            "features evaluation did not finish within 30 s",
        )),
    }
}

/// Arms the features pump. Disarmed on a follower, which has no authority evidence of its own.
pub(super) fn arm_features_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    posture: NodePosture,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    sources: FeatureSources,
    trigger: FeatureTrigger,
) {
    let FeatureTrigger { request, evaluated } = trigger;
    if posture == NodePosture::Follower {
        tracing::warn!("follower posture: features pump stays disarmed");
        return;
    }
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + EVALUATE_INTERVAL,
            EVALUATE_INTERVAL,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut revisions = sources.snapshot.subscribe();
        loop {
            let now = OffsetDateTime::now_utc();
            let published = match evaluate(&sources, now).await {
                Ok(value) => publish(&read_model, value, now),
                Err(error) => Err(error),
            };
            if let Err(error) = &published {
                tracing::error!("features evaluation failed: {error}");
            }
            evaluated.send_modify(|evaluation| {
                evaluation.count = evaluation.count.saturating_add(1);
                evaluation.failure = published.err();
            });
            tokio::select! {
                _ = ticker.tick() => {}
                _ = revisions.changed() => {}
                _ = request.notified() => {}
            }
        }
    });
}

/// The enabled capabilities, grouped by toolset, then the services.
fn rows_of(snapshot: &Snapshot) -> Vec<Row> {
    let mut capabilities = Vec::new();
    let mut services = Vec::new();
    for object in &snapshot.objects {
        match &object.config {
            ObjectConfig::Capability(capability) if object.enters_listing() => {
                capabilities.push(Row {
                    id: object.id.clone(),
                    title: object.id.clone(),
                    area: capability
                        .toolset
                        .clone()
                        .unwrap_or_else(|| NO_TOOLSET_AREA.to_owned()),
                    service: false,
                    tests: capability.tests.clone(),
                    probes: capability.probes.clone(),
                });
            }
            ObjectConfig::Feature(service) if service.enabled => services.push(Row {
                id: object.id.clone(),
                title: service.title.clone(),
                area: SERVICES_AREA.to_owned(),
                service: true,
                tests: Vec::new(),
                probes: service.probes.clone(),
            }),
            _ => {}
        }
    }
    capabilities.sort_by(|left, right| (&left.area, &left.id).cmp(&(&right.area, &right.id)));
    services.sort_by(|left, right| left.id.cmp(&right.id));
    capabilities.extend(services);
    capabilities
}

/// One evaluation: the pinned snapshot's rows, their tests read from the gate evidence and their probes run.
async fn evaluate(sources: &FeatureSources, now: OffsetDateTime) -> Result<Value, String> {
    let snapshot = sources.snapshot.current();
    let rows = rows_of(&snapshot);
    let (tested, commit) = read_evidence(sources, &snapshot).await?;

    let test_results: Vec<Vec<CheckResult>> = rows
        .iter()
        .map(|row| {
            row.tests
                .iter()
                .map(|key| test_outcome(key, &tested))
                .collect()
        })
        .collect();

    // Every probe starts as "not evaluated"; each path below overwrites its own slot.
    let mut probe_results: Vec<Vec<CheckResult>> = rows
        .iter()
        .map(|row| {
            row.probes
                .iter()
                .map(|text| CheckResult::new(text, ProbeState::Unknown, "not evaluated"))
                .collect()
        })
        .collect();
    let mut hosts: BTreeMap<String, Vec<(usize, usize, String, Probe)>> = BTreeMap::new();
    let mut http = Vec::new();
    let mut models = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        for (slot, text) in row.probes.iter().enumerate() {
            let parsed = match Probe::parse(text) {
                Ok(parsed) => parsed,
                Err(error) => {
                    probe_results[index][slot] = CheckResult::new(
                        text,
                        ProbeState::Fail,
                        format!("probe does not parse: {error}"),
                    );
                    continue;
                }
            };
            match &parsed {
                Probe::Unit { host, .. } | Probe::File { host, .. } => hosts
                    .entry(host.clone())
                    .or_default()
                    .push((index, slot, text.clone(), parsed.clone())),
                Probe::Http { url } => http.push((index, slot, text.clone(), url.clone())),
                Probe::Models { lane } => models.push((index, slot, text.clone(), lane.clone())),
            }
        }
    }

    let probes = hosts.into_iter().map(|(host, items)| {
        let place = host_place(&snapshot, &host, &sources.local_node);
        let ssh = sources.ssh.clone();
        let slots: Vec<(usize, usize)> = items.iter().map(|item| (item.0, item.1)).collect();
        let texts: Vec<String> = items.iter().map(|item| item.2.clone()).collect();
        let checks: Vec<Probe> = items.into_iter().map(|item| item.3).collect();
        async move {
            let outcomes = probe_host(ssh, host, place, texts, checks).await;
            (slots, outcomes)
        }
    });
    for (slots, outcomes) in futures_util::future::join_all(probes).await {
        for ((index, slot), outcome) in slots.into_iter().zip(outcomes) {
            probe_results[index][slot] = outcome;
        }
    }
    for (index, slot, text, url) in http {
        let (state, detail) = http_outcome(&url).await;
        probe_results[index][slot] = CheckResult::new(&text, state, detail);
    }
    for (index, slot, text, lane) in models {
        let (state, detail) = models_outcome(sources.gateway.clone(), lane).await;
        probe_results[index][slot] = CheckResult::new(&text, state, detail);
    }

    let sha = match &tested {
        Ok(Some(tested)) => tested.sha.as_deref().map_or("unknown", short_sha),
        _ => "unknown",
    };
    let mut tested_capabilities = 0;
    let rows_json: Vec<Value> = rows
        .iter()
        .zip(test_results.into_iter().zip(probe_results))
        .map(|(row, (tests, probes))| {
            let Status { tone, label } = if row.service {
                service_status(&probes)
            } else {
                capability_status(&tests, &probes, sha)
            };
            if !row.service
                && !tests.is_empty()
                && tests.iter().all(|test| test.state == ProbeState::Pass)
            {
                tested_capabilities += 1;
            }
            let checks: Vec<CheckResult> = tests.into_iter().chain(probes).collect();
            json!({
                "id": row.id,
                "title": row.title,
                "area": row.area,
                "service": row.service,
                "status": tone,
                "label": label,
                "checks": checks,
            })
        })
        .collect();
    let capabilities = rows.iter().filter(|row| !row.service).count();

    let tested_value = tested_evidence(&tested, commit.as_deref());
    Ok(json!({
        "evaluatedAt": rfc3339(now),
        "tested": tested_value,
        "live": {"registryRevision": snapshot.revision, "commit": commit},
        "counts": {"capabilities": capabilities, "tested": tested_capabilities},
        "rows": rows_json,
    }))
}

/// The gate's record for the deployed commit. `inherited` is null while either commit is unknown:
/// an unread deployment is not evidence that the tested commit is the live one.
fn tested_evidence(tested: &Result<Option<Tested>, String>, commit: Option<&str>) -> Value {
    match tested {
        Ok(Some(tested)) => {
            let inherited = match (tested.sha.as_deref(), commit) {
                (Some(sha), Some(commit)) => Some(sha != commit),
                _ => None,
            };
            json!({"sha": tested.sha, "at": tested.at, "inherited": inherited})
        }
        _ => Value::Null,
    }
}

/// Reads the deployed gate evidence and the commit of the pinned revision, off the async runtime.
async fn read_evidence(
    sources: &FeatureSources,
    snapshot: &Snapshot,
) -> Result<(Result<Option<Tested>, String>, Option<String>), String> {
    let tested_path = sources.state_root.join("tested.json");
    let store = SnapshotStore::new(sources.registry_snapshot.clone());
    let revision = snapshot.revision;
    tokio::task::spawn_blocking(move || {
        let tested = read_tested(&tested_path);
        let commit = store
            .load_verified_publication()
            .ok()
            .filter(|(_, receipt)| receipt.revision == revision)
            .map(|(_, receipt)| receipt.commit);
        (tested, commit)
    })
    .await
    .map_err(|error| format!("reading deployed evidence: {error}"))
}

fn read_tested(path: &Path) -> Result<Option<Tested>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("{}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// One named test against the deployed gate results. The gate fails a commit whose named test is
/// absent or red, so an absent key here means the registry moved past the tested commit.
fn test_outcome(key: &str, tested: &Result<Option<Tested>, String>) -> CheckResult {
    let tested = match tested {
        Ok(Some(tested)) if !tested.tests.is_empty() => tested,
        Ok(_) => return CheckResult::new(key, ProbeState::Unknown, "no gate results deployed"),
        Err(error) => {
            return CheckResult::new(
                key,
                ProbeState::Unknown,
                format!("gate results unreadable: {error}"),
            );
        }
    };
    let sha = tested.sha.as_deref().map_or("unknown", short_sha);
    match tested.tests.get(key).map(String::as_str) {
        Some("pass") => CheckResult::new(key, ProbeState::Pass, format!("passed at {sha}")),
        Some("fail") => CheckResult::new(key, ProbeState::Fail, format!("failed at {sha}")),
        Some(other) => CheckResult::new(key, ProbeState::Unknown, format!("{other} at {sha}")),
        None => CheckResult::new(key, ProbeState::Fail, format!("named test absent at {sha}")),
    }
}

fn short_sha(sha: &str) -> &str {
    sha.get(..7).unwrap_or(sha)
}

/// Where a declared host is probed: its tailscale name, and whether its node is this one.
struct HostPlace {
    tailscale: String,
    local: bool,
}

fn host_place(snapshot: &Snapshot, host: &str, local_node: &str) -> Option<HostPlace> {
    let object = snapshot.object(RegistryKind::Host, host)?;
    let ObjectConfig::Host(declared) = &object.config else {
        return None;
    };
    if !(declared.enabled && declared.enrolled) {
        return None;
    }
    let node = snapshot
        .listed_objects(RegistryKind::Node)
        .find_map(|node| match &node.config {
            ObjectConfig::Node(declared) if declared.enabled && declared.host == host => {
                Some(node.id.as_str())
            }
            _ => None,
        })?;
    Some(HostPlace {
        tailscale: declared.tailscale.clone(),
        local: node == local_node,
    })
}

/// Evaluates one host's `unit:` and `file:` checks. Results keep the order of `texts`; a host
/// that cannot be reached marks every one of its checks unknown.
async fn probe_host(
    ssh: PathBuf,
    host: String,
    place: Option<HostPlace>,
    texts: Vec<String>,
    checks: Vec<Probe>,
) -> Vec<CheckResult> {
    let Some(place) = place else {
        return unknown_all(
            &texts,
            &format!("{host} unreachable: not an enabled enrolled host"),
        );
    };
    let answered = if place.local {
        local_probe(checks).await
    } else {
        remote_probe(&ssh, &place.tailscale, &texts).await
    };
    match answered {
        Ok(results) if results.len() == texts.len() => texts
            .iter()
            .zip(results)
            .map(|(text, result)| CheckResult::new(text, result.state, result.detail))
            .collect(),
        Ok(results) => unknown_all(
            &texts,
            &format!(
                "{host} unreachable: answered {} of {} checks",
                results.len(),
                texts.len()
            ),
        ),
        Err(error) => unknown_all(&texts, &format!("{host} unreachable: {error}")),
    }
}

fn unknown_all(texts: &[String], detail: &str) -> Vec<CheckResult> {
    texts
        .iter()
        .map(|text| CheckResult::new(text, ProbeState::Unknown, detail))
        .collect()
}

async fn local_probe(checks: Vec<Probe>) -> Result<Vec<ProbeResult>, String> {
    let now = OffsetDateTime::now_utc();
    let joined = tokio::time::timeout(
        PROBE_BOUND,
        tokio::task::spawn_blocking(move || probe(&checks, now)),
    )
    .await
    .map_err(|_| "probe timed out".to_owned())?;
    joined.map_err(|error| error.to_string())
}

/// Runs `odin feature-probe` on the declared host over the registered SSH path. The checks
/// travel as one shell-quoted JSON argument, so the remote shell reads them literally.
async fn remote_probe(
    ssh: &Path,
    tailscale: &str,
    texts: &[String],
) -> Result<Vec<ProbeResult>, String> {
    let json = serde_json::to_string(texts).map_err(|error| error.to_string())?;
    let command = format!(
        "odin feature-probe --checks {}",
        odin_process::shell_quote(&json)
    );
    let argv = odin_omp::live::harness::ssh_argv(&["-T"], tailscale, &[command.as_str()]);
    let output = tokio::time::timeout(
        PROBE_BOUND,
        Command::new(ssh)
            .args(&argv)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "ssh timed out".to_owned())?
    .map_err(|error| format!("ssh did not start: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr.lines().next().unwrap_or_default().trim();
        return Err(format!("ssh failed ({}): {first}", output.status));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("unreadable probe answer: {error}"))
}

static HTTP: LazyLock<Result<reqwest::Client, String>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(PROBE_BOUND)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())
});

/// One HTTP probe: 2xx passes, other answers fail with their status, and a timeout or refused
/// connection fails too. Redirects are not followed.
async fn http_outcome(url: &str) -> (ProbeState, String) {
    let client = match HTTP.as_ref() {
        Ok(client) => client,
        Err(error) => {
            return (
                ProbeState::Unknown,
                format!("http client unavailable: {error}"),
            )
        }
    };
    match client.get(url).send().await {
        Ok(response) if response.status().is_success() => (
            ProbeState::Pass,
            format!("HTTP {}", response.status().as_u16()),
        ),
        Ok(response) => (
            ProbeState::Fail,
            format!("HTTP {}", response.status().as_u16()),
        ),
        Err(error) if error.is_timeout() => (ProbeState::Fail, "timed out".to_owned()),
        Err(error) if error.is_connect() => (ProbeState::Fail, "connect failed".to_owned()),
        Err(_) => (ProbeState::Fail, "request failed".to_owned()),
    }
}

/// One `models:` check: the lane's account is open, or held. A refused or keyless account
/// fails; any other hold is unknown.
async fn models_outcome(gateway: Option<String>, lane: String) -> (ProbeState, String) {
    let Some(gateway) = gateway else {
        return (
            ProbeState::Unknown,
            "model gateway is not configured".to_owned(),
        );
    };
    let named = lane.clone();
    let joined = tokio::time::timeout(
        PROBE_BOUND,
        tokio::task::spawn_blocking(move || odin_hermes::runtime::lane_standing(&gateway, &named)),
    )
    .await;
    let standing = match joined {
        Err(_) => return (ProbeState::Unknown, "model book read timed out".to_owned()),
        Ok(Err(error)) => {
            return (
                ProbeState::Unknown,
                format!("model book unreadable: {error}"),
            )
        }
        Ok(Ok(Err(error))) => {
            return (
                ProbeState::Unknown,
                format!("model book unreadable: {error}"),
            );
        }
        Ok(Ok(Ok(standing))) => standing,
    };
    match standing {
        odin_hermes::runtime::LaneStanding::Undeclared => {
            (ProbeState::Fail, format!("lane {lane} is not declared"))
        }
        odin_hermes::runtime::LaneStanding::Open => (ProbeState::Pass, "open".to_owned()),
        odin_hermes::runtime::LaneStanding::Held(reason) => {
            if reason.starts_with("refused upstream") || reason.starts_with("no key") {
                (ProbeState::Fail, reason)
            } else {
                (ProbeState::Unknown, format!("held: {reason}"))
            }
        }
    }
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

/// Upserts the `Status/features` object. The evaluation time is in the body, so every pass
/// is a new revision.
fn publish(
    read_model: &odin_huginn::read_model::MaterializedReadModel,
    value: Value,
    observed_at: OffsetDateTime,
) -> Result<(), String> {
    let object = live::ObjectRef {
        kind: live::ObjectKind::Status,
        id: STATUS_ID.to_owned(),
    };
    let current = read_model.get(&object).map_err(|error| error.to_string())?;
    let revision = current.map_or(1, |current| current.revision.get().saturating_add(1));
    let encoded = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    read_model
        .upsert(live::ObjectSnapshot {
            object,
            revision: live::Revision::new(revision),
            revision_source: live::RevisionSource::Kernel,
            freshness: live::Freshness {
                state: live::FreshnessState::Fresh,
                observed_at,
                source_updated_at: Some(observed_at),
                stale_after_seconds: None,
            },
            content_digest: odin_domain::Digest::hash(&encoded),
            value,
        })
        .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deployed record as the gate writes it: `<junit classname> <junit name>` to the outcome.
    fn deployed() -> Result<Option<Tested>, String> {
        serde_json::from_value(json!({
            "sha": "0123456789abcdef",
            "tests": {
                "odin-omp host_tools::delegation::tests::read_is_parent_scoped_and_reports_real_lifecycle": "pass",
                "odin-cli::bin/odind coding_route::tests::a_merge_that_fails": "fail",
            }
        }))
        .map(Some)
        .map_err(|error| error.to_string())
    }

    #[test]
    fn a_named_test_reads_its_gate_outcome_and_an_absent_one_is_red() {
        let tested = deployed();
        let passed = test_outcome(
            "odin-omp host_tools::delegation::tests::read_is_parent_scoped_and_reports_real_lifecycle",
            &tested,
        );
        assert_eq!(
            (passed.state, passed.detail.as_str()),
            (ProbeState::Pass, "passed at 0123456")
        );
        let failed = test_outcome(
            "odin-cli::bin/odind coding_route::tests::a_merge_that_fails",
            &tested,
        );
        assert_eq!(failed.state, ProbeState::Fail);
        let absent = test_outcome("odin-cli::bin/odind renamed::away", &tested);
        assert_eq!(
            (absent.state, absent.detail.as_str()),
            (ProbeState::Fail, "named test absent at 0123456")
        );
        let nothing = test_outcome("odin-cli x", &Ok(None));
        assert_eq!(nothing.state, ProbeState::Unknown);
    }
}
