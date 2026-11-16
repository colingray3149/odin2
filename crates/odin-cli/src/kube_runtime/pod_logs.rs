//! Reading a workload's pod logs through the kube API.

use time::OffsetDateTime;

/// A running pod's status delta: its newest
/// `ODIN-STATUS` against the one before, from a bounded timestamped log tail
/// through the kube API. `None` when it reports no status or the read fails.
pub(super) async fn pod_status(client: &odin_kube::KubeClient, job: &str) -> Option<String> {
    use kube::api::{ListParams, LogParams};
    let pods = client
        .pods()
        .list(&ListParams::default().labels(&format!("job-name={job}")))
        .await
        .ok()?;
    let pod = pods.items.iter().find(|pod| {
        pod.status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            == Some("Running")
    })?;
    let log = client
        .pods()
        .logs(
            pod.metadata.name.as_deref()?,
            &LogParams {
                tail_lines: Some(odin_kube::telemetry::STATUS_TAIL_LINES),
                timestamps: true,
                ..LogParams::default()
            },
        )
        .await
        .ok()?;
    odin_kube::telemetry::status_delta(&log, OffsetDateTime::now_utc())
}

/// The newest `lines` of the job's newest pod's log, redacted; a log that
/// cannot be read is one line naming why.
pub(super) async fn pod_log(client: &odin_kube::KubeClient, job: &str, lines: i64) -> Vec<String> {
    use kube::api::{ListParams, LogParams};
    let pods = match client
        .pods()
        .list(&ListParams::default().labels(&format!("job-name={job}")))
        .await
    {
        Ok(pods) => pods,
        Err(error) => return vec![format!("the pod list is unreadable: {error}")],
    };
    let Some(name) = pods
        .items
        .iter()
        .max_by_key(|pod| pod.metadata.creation_timestamp.clone())
        .and_then(|pod| pod.metadata.name.clone())
    else {
        return vec![format!("job {job} has no pod left to read")];
    };
    match client
        .pods()
        .logs(
            &name,
            &LogParams {
                tail_lines: Some(lines),
                timestamps: true,
                limit_bytes: Some(64 * 1024),
                ..LogParams::default()
            },
        )
        .await
    {
        Ok(log) => odin_omp::redact::redact_text(&log)
            .lines()
            .map(str::to_owned)
            .collect(),
        Err(error) => vec![format!("pod {name}'s log is unreadable: {error}")],
    }
}
