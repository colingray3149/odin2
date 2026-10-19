//! One bounded, read-only cluster health observation.
//!
//! Scans nodes, pods, and warning events using the configured [`KubeClient`].
//! Inventory beyond the scan limits fails rather than returning partial health.

use std::collections::HashSet;

use k8s_openapi::api::core::v1::{ContainerStatus, Event, Node, Pod};
use kube::api::ListParams;
use odin_domain::huginn::{
    KubeClusterHealth, KubeContainerIssue, KubeNodeHealth, KubeNodePressure, KubePodProblem,
    KubeWarningEvent,
};

use crate::client::{KubeClient, KubeError};
use crate::placement::node_facts;

/// Bounded node inventory; a cluster with more nodes fails closed.
const NODE_SCAN_LIMIT: u32 = 1024;
/// Bounded pod inventory; a cluster with more pods fails closed.
const POD_SCAN_LIMIT: u32 = 4096;
/// Bounded warning-event scan.
const EVENT_SCAN_LIMIT: u32 = 512;
/// The report carries at most this many warning events, most recent first.
const MAX_REPORTED_EVENTS: usize = 200;

/// Lists node readiness and pressure, pods with observed problems, and
/// recent warning events in one bounded read. The cluster identity is the
/// client's logical cluster label; timestamps are the API server's own
/// RFC 3339 strings, never locally reformatted.
pub async fn cluster_health(client: &KubeClient) -> Result<KubeClusterHealth, KubeError> {
    let node_api: kube::Api<Node> = kube::Api::all(client.client.clone());
    let pod_api: kube::Api<Pod> = kube::Api::all(client.client.clone());
    let event_api: kube::Api<Event> = kube::Api::all(client.client.clone());

    let nodes = tokio::time::timeout(
        client.config.request_timeout,
        node_api.list(&ListParams::default().limit(NODE_SCAN_LIMIT)),
    )
    .await
    .map_err(|_| KubeError::unavailable("node health observation timed out"))??;
    if nodes
        .metadata
        .continue_
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(KubeError::unavailable(
            "node inventory exceeds the bounded health scan",
        ));
    }

    let pods = tokio::time::timeout(
        client.config.request_timeout,
        pod_api.list(&ListParams::default().limit(POD_SCAN_LIMIT)),
    )
    .await
    .map_err(|_| KubeError::unavailable("pod health observation timed out"))??;
    if pods
        .metadata
        .continue_
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(KubeError::unavailable(
            "pod inventory exceeds the bounded health scan",
        ));
    }

    let events = tokio::time::timeout(
        client.config.request_timeout,
        event_api.list(
            &ListParams::default()
                .fields("type=Warning")
                .limit(EVENT_SCAN_LIMIT),
        ),
    )
    .await
    .map_err(|_| KubeError::unavailable("warning event observation timed out"))??;
    if events
        .metadata
        .continue_
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(KubeError::unavailable(
            "warning event inventory exceeds the bounded health scan",
        ));
    }

    let node_rows = nodes
        .items
        .iter()
        .map(node_health)
        .collect::<Result<Vec<_>, KubeError>>()?;
    let mut pod_problems = Vec::new();
    for pod in &pods.items {
        if let Some(problem) = pod_problem(pod) {
            pod_problems.push(problem);
        }
    }
    let mut warning_events = events
        .items
        .iter()
        .filter_map(warning_event)
        .collect::<Vec<_>>();
    warning_events.sort_by(|left, right| right.last_timestamp.cmp(&left.last_timestamp));
    warning_events.truncate(MAX_REPORTED_EVENTS);
    Ok(KubeClusterHealth {
        cluster: client.config.cluster.clone(),
        observed_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| KubeError::unavailable("cluster clock cannot format the observation"))?,
        nodes: node_rows,
        pods_observed: pods.items.len() as u32,
        pod_problems,
        warning_events,
    })
}

/// Readiness uses placement's precedence: unschedulable, Ready, then Unknown.
fn node_health(node: &Node) -> Result<KubeNodeHealth, KubeError> {
    let metadata = &node.metadata;
    let name = metadata
        .name
        .as_deref()
        .ok_or_else(|| KubeError::rejected("node inventory carries an unnamed node"))?;
    let uid = metadata
        .uid
        .as_deref()
        .ok_or_else(|| KubeError::rejected("node inventory carries a node without a uid"))?;
    let facts = node_facts(node)?;
    let pressures = node
        .status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .into_iter()
        .flatten()
        .filter(|condition| {
            matches!(
                condition.type_.as_str(),
                "MemoryPressure" | "DiskPressure" | "PIDPressure"
            )
        })
        .map(|condition| KubeNodePressure {
            kind: condition.type_.clone(),
            status: condition.status.clone(),
        })
        .collect();
    Ok(KubeNodeHealth {
        name: name.to_owned(),
        uid: uid.to_owned(),
        state: facts.state,
        architecture: facts.architecture,
        operating_system: facts.operating_system,
        pressures,
        unschedulable: facts.unschedulable,
        capacity: facts.capacity,
        allocatable: facts.allocatable,
    })
}

/// Returns the pod's problem row when the observation flags it: phase
/// outside `Running`/`Succeeded`, a running pod reporting no container, or a
/// running pod with a not-ready or waiting container. Init containers count
/// when they wait (a crash-looping native sidecar) and, for native sidecars
/// (`restartPolicy: Always`), when they are not ready; a completed one-shot
/// init container is not ready by design. Completed (`Succeeded`) and fully
/// ready running pods are healthy rows and return `None`.
fn pod_problem(pod: &Pod) -> Option<KubePodProblem> {
    let metadata = &pod.metadata;
    let phase = pod.status.as_ref().and_then(|status| status.phase.clone());
    if phase.as_deref() == Some("Succeeded") {
        return None;
    }
    let sidecars: HashSet<&str> = pod
        .spec
        .iter()
        .flat_map(|spec| spec.init_containers.iter().flatten())
        .filter(|container| container.restart_policy.as_deref() == Some("Always"))
        .map(|container| container.name.as_str())
        .collect();
    let issue = |container: &ContainerStatus| KubeContainerIssue {
        name: container.name.clone(),
        image: container.image.clone(),
        ready: container.ready,
        restart_count: u32::try_from(container.restart_count).unwrap_or(0),
        waiting_reason: container
            .state
            .as_ref()
            .and_then(|state| state.waiting.as_ref())
            .and_then(|waiting| waiting.reason.clone())
            .filter(|reason| !reason.is_empty()),
    };
    let status = pod.status.as_ref();
    let mut containers: Vec<KubeContainerIssue> = status
        .and_then(|status| status.container_statuses.as_ref())
        .into_iter()
        .flatten()
        .map(issue)
        .collect();
    let app_containers = containers.len();
    containers.extend(
        status
            .and_then(|status| status.init_container_statuses.as_ref())
            .into_iter()
            .flatten()
            .map(|container| (sidecars.contains(container.name.as_str()), issue(container)))
            .filter(|(sidecar, issue)| *sidecar || issue.waiting_reason.is_some())
            .map(|(_, issue)| issue),
    );
    let running = phase.as_deref() == Some("Running");
    let running_clean = running
        && app_containers > 0
        && containers
            .iter()
            .all(|container| container.ready && container.waiting_reason.is_none());
    if running_clean {
        return None;
    }
    Some(KubePodProblem {
        namespace: metadata.namespace.clone().unwrap_or_default(),
        name: metadata.name.clone().unwrap_or_default(),
        uid: metadata.uid.clone().unwrap_or_default(),
        node: pod.spec.as_ref().and_then(|spec| spec.node_name.clone()),
        reason: status
            .and_then(|status| status.reason.clone())
            .filter(|reason| !reason.is_empty()),
        phase,
        containers,
    })
}

/// Projects one API event into a warning row; non-warning events (already
/// filtered server-side by the field selector) return `None`. Timestamps
/// keep the API server's RFC 3339 formatting verbatim.
fn warning_event(event: &Event) -> Option<KubeWarningEvent> {
    if event.type_.as_deref() != Some("Warning") {
        return None;
    }
    let involved = &event.involved_object;
    Some(KubeWarningEvent {
        namespace: involved.namespace.clone(),
        involved_kind: involved.kind.clone().unwrap_or_default(),
        involved_name: involved.name.clone().unwrap_or_default(),
        reason: event.reason.clone().unwrap_or_default(),
        message: event.message.clone().unwrap_or_default(),
        count: u32::try_from(event.count.unwrap_or(1)).unwrap_or(1),
        first_timestamp: event.first_timestamp.as_ref().map(|at| at.0.to_string()),
        last_timestamp: event.last_timestamp.as_ref().map(|at| at.0.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod(value: serde_json::Value) -> Pod {
        serde_json::from_value(value).expect("pod fixture")
    }

    fn container(name: &str, ready: bool, waiting: Option<&str>) -> serde_json::Value {
        let state = match waiting {
            Some(reason) => json!({"waiting": {"reason": reason}}),
            None if ready => json!({"running": {}}),
            None => json!({"terminated": {"exitCode": 0, "reason": "Completed"}}),
        };
        json!({"name": name, "image": "img", "imageID": "", "ready": ready, "restartCount": 0, "state": state})
    }

    fn running(
        init: serde_json::Value,
        statuses: serde_json::Value,
        init_statuses: serde_json::Value,
    ) -> Pod {
        pod(json!({
            "metadata": {"name": "p", "namespace": "odin", "uid": "u"},
            "spec": {"containers": [{"name": "worker"}], "initContainers": init},
            "status": {"phase": "Running", "containerStatuses": statuses, "initContainerStatuses": init_statuses},
        }))
    }

    #[test]
    fn a_ready_pod_with_a_completed_one_shot_init_container_is_healthy() {
        let pod = running(
            json!([{"name": "setup"}]),
            json!([container("worker", true, None)]),
            json!([container("setup", false, None)]),
        );
        assert!(pod_problem(&pod).is_none());
    }

    #[test]
    fn a_crash_looping_native_sidecar_is_a_problem() {
        let pod = running(
            json!([{"name": "browser", "restartPolicy": "Always"}]),
            json!([container("worker", true, None)]),
            json!([container("browser", false, Some("CrashLoopBackOff"))]),
        );
        let problem = pod_problem(&pod).expect("the browser sidecar is down");
        assert!(problem
            .containers
            .iter()
            .any(|issue| issue.name == "browser"
                && issue.waiting_reason.as_deref() == Some("CrashLoopBackOff")));
        let unready = running(
            json!([{"name": "browser", "restartPolicy": "Always"}]),
            json!([container("worker", true, None)]),
            json!([container("browser", false, None)]),
        );
        assert!(
            pod_problem(&unready).is_some(),
            "an unready sidecar is a problem"
        );
    }

    #[test]
    fn a_waiting_one_shot_init_is_a_problem() {
        let waiting = running(
            json!([{"name": "setup"}]),
            json!([container("worker", true, None)]),
            json!([container("setup", false, Some("CrashLoopBackOff"))]),
        );
        let problem = pod_problem(&waiting).expect("a waiting one-shot init is a problem");
        assert!(problem.containers.iter().any(|issue| {
            issue.name == "setup" && issue.waiting_reason.as_deref() == Some("CrashLoopBackOff")
        }));
        let sidecar = running(
            json!([{"name": "browser", "restartPolicy": "Always"}]),
            json!([container("worker", true, None)]),
            json!([container("browser", true, None)]),
        );
        assert!(
            pod_problem(&sidecar).is_none(),
            "a ready native sidecar is not a problem"
        );
    }

    #[test]
    fn a_running_pod_reporting_no_container_is_a_problem() {
        let pod = running(json!([]), json!([]), json!([]));
        let problem = pod_problem(&pod).expect("a running pod with no container is a problem");
        assert_eq!(problem.phase.as_deref(), Some("Running"));
        assert!(problem.containers.is_empty());
    }

    #[test]
    fn node_health_reports_the_node_facts_state() {
        let node = |unschedulable: bool, ready: Option<&str>| -> Node {
            let mut status = json!({
                "nodeInfo": {"architecture": "amd64"},
                "capacity": {"cpu": "4"},
            });
            if let Some(ready) = ready {
                status["conditions"] = json!([{"type": "Ready", "status": ready}]);
            }
            serde_json::from_value(json!({
                "metadata": {"name": "mini", "uid": "node-uid"},
                "spec": {"unschedulable": unschedulable},
                "status": status,
            }))
            .expect("node fixture")
        };
        for (unschedulable, ready) in [
            (true, Some("True")),
            (false, Some("False")),
            (false, None::<&str>),
        ] {
            let node = node(unschedulable, ready);
            let facts = node_facts(&node).expect("node facts");
            let health = node_health(&node).expect("node health");
            assert_eq!(health.state, facts.state);
            assert_eq!(health.unschedulable, facts.unschedulable);
            assert_eq!(health.architecture, facts.architecture);
            assert_eq!(health.capacity, facts.capacity);
        }
    }
}
