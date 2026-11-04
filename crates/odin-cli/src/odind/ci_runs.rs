//! The overview's CI line, read once for every view: gh's newest run per declared repo, kept as the
//! `Status/ci` object. While any Huginn client is connected the pump reads the runs every minute and
//! publishes the rows when they changed; `odin view` reads the object with the rest of the Status snapshot.
//! gh runs as odind's user on the authority: its own login, or a `GH_TOKEN` in odind's environment,
//! is the credential; without one each row carries gh's error.

use std::sync::Arc;
use std::time::{Duration, Instant};

use odin_huginn::NodePosture;
use serde_json::{json, Value};

/// How often a connected client gets fresh runs.
const CI_EVERY: Duration = Duration::from_secs(60);
/// How often the pump looks for a connected client, so a view opened after an idle spell waits seconds, not a minute.
const CHECK_EVERY: Duration = Duration::from_secs(5);
const GH_BOUND: Duration = Duration::from_secs(20);
const STATUS_ID: &str = "ci";

/// The CI repos the overview tracks: enabled registry projects' `repo` key.
fn declared_repos(registry: &odin_registry::Snapshot) -> Vec<String> {
    let mut repos: Vec<String> = registry
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            odin_registry::ObjectConfig::Project(project) if project.enabled => {
                project.repo.clone()
            }
            _ => None,
        })
        .collect();
    repos.sort();
    repos.dedup();
    repos
}

/// gh's newest runs for one repo as JSON text, or why they could not be read.
async fn gh_runs(repo: &str) -> Result<String, String> {
    let read = tokio::process::Command::new("gh")
        .arg("-R")
        .arg(repo)
        .args([
            "run",
            "list",
            "--limit",
            "1",
            "--json",
            "status,conclusion,headBranch,updatedAt",
        ])
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(GH_BOUND, read)
        .await
        .map_err(|error| format!("gh did not answer within {} s: {error}", GH_BOUND.as_secs()))?
        .map_err(|error| format!("gh could not run: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "the authority's gh: {}",
            first_line(&String::from_utf8_lossy(&output.stderr))
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// gh's errors are one line; keep that line so the CI row stays one line.
fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("gh failed without a message")
        .trim()
        .to_owned()
}

/// The CI row for one repo: gh's own run fields, `no runs` when the list is
/// empty, or the failure (gh's, or output that is not a run list) that names
/// its cause.
fn ci_row(repo: &str, gh: Result<&str, &str>) -> Value {
    let body = match gh {
        Ok(body) => body,
        Err(cause) => return json!({ "repo": repo, "error": cause }),
    };
    let runs: Vec<Value> = match serde_json::from_str(body) {
        Ok(runs) => runs,
        Err(error) => {
            return json!({ "repo": repo, "error": format!("gh run list is not JSON: {error}") })
        }
    };
    let Some(run) = runs.into_iter().next() else {
        return json!({ "repo": repo, "status": "no runs" });
    };
    json!({
        "repo": repo,
        "status": run.get("status").cloned().unwrap_or(Value::Null),
        "conclusion": run.get("conclusion").cloned().unwrap_or(Value::Null),
        "branch": run.get("headBranch").cloned().unwrap_or(Value::Null),
        "updatedAt": run.get("updatedAt").cloned().unwrap_or(Value::Null),
    })
}

/// Reads every declared repo's newest run and publishes the rows when they changed.
async fn publish(
    registry: &odin_registry::SnapshotHandle,
    read_model: &odin_huginn::read_model::MaterializedReadModel,
) -> Result<bool, String> {
    let mut rows = Vec::new();
    for repo in declared_repos(&registry.current()) {
        let runs = gh_runs(&repo).await;
        rows.push(ci_row(&repo, runs.as_deref().map_err(String::as_str)));
    }
    crate::huginn_spend::publish_status(
        read_model,
        crate::huginn_spend::status_object(STATUS_ID),
        json!({ "rows": rows }),
        time::OffsetDateTime::now_utc(),
    )
}

/// Arms the CI pump. Only the authority reads CI, so a follower leaves it disarmed; nothing runs
/// while no client is connected.
pub(super) fn arm_ci_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    posture: NodePosture,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    registry: Arc<odin_registry::SnapshotHandle>,
    connections: odin_huginn::ConnectionRegistry,
) {
    if posture == NodePosture::Follower {
        tracing::warn!("follower posture: CI pump stays disarmed; the authority reads CI");
        return;
    }
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(CHECK_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut read_at: Option<Instant> = None;
        loop {
            ticker.tick().await;
            if connections.active_connections() == 0
                || read_at.is_some_and(|at| at.elapsed() < CI_EVERY)
            {
                continue;
            }
            read_at = Some(Instant::now());
            if let Err(error) = publish(&registry, &read_model).await {
                tracing::error!("CI publication failed: {error}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CI row carries gh's own run fields, an empty run list says so,
    /// and a failed gh names its cause on the line.
    #[test]
    fn ci_row_names_the_run_and_the_failure() {
        let run = r#"[{"status":"completed","conclusion":"success","headBranch":"main","updatedAt":"2026-10-19T16:04:42Z"}]"#;
        let row = ci_row("odin-owner/odin", Ok(run));
        assert_eq!(row["repo"], json!("odin-owner/odin"));
        assert_eq!(row["status"], json!("completed"));
        assert_eq!(row["conclusion"], json!("success"));
        assert_eq!(row["branch"], json!("main"));
        assert_eq!(row["updatedAt"], json!("2026-10-19T16:04:42Z"));
        assert_eq!(
            ci_row("odin-owner/odin", Ok("[]"))["status"],
            json!("no runs")
        );
        let row = ci_row("odin-owner/odin", Ok("To get started with GitHub CLI"));
        assert!(row.get("status").is_none());
        assert!(row["error"]
            .as_str()
            .is_some_and(|error| error.starts_with("gh run list is not JSON")));
        let row = ci_row(
            "odin-owner/dotfiles",
            Err("failed to get runs: HTTP 404: Not Found"),
        );
        assert_eq!(
            row["error"],
            json!("failed to get runs: HTTP 404: Not Found")
        );
    }
}
