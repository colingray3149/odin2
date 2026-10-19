//! Node administration using the configured [`KubeClient`].
//!
//! Drain cordons before eviction and reports refusals or pods that remain
//! at the deadline in [`DrainReport::remained`]. Only terminal pods are
//! deleted directly; eviction refusals must not bypass disruption budgets.
//! DaemonSet pods would be recreated, and static mirror pods cannot be
//! removed through the API, so neither is evicted or counted as remained.

use std::time::Duration;

use k8s_openapi::api::core::v1::{Node, Pod};
use kube::api::{Api, DeleteParams, EvictParams, ListParams, Patch, PatchParams};

use crate::client::{KubeClient, KubeError};

/// Refuse inventories above this limit rather than drain only part of a node.
pub(crate) const POD_SCAN_LIMIT: u32 = 4096;

/// Poll cadence while waiting for an evicted pod to leave. Deliberately
/// coarse: eviction is a graceful teardown measured in seconds.
const ABSENCE_POLL: Duration = Duration::from_millis(500);

/// `evicted` contains pods confirmed absent; `remained` contains drainable
/// pods not removed before the deadline, including refused evictions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainReport {
    pub node: String,
    pub cordoned: bool,
    pub evicted: Vec<String>,
    pub remained: Vec<String>,
}

pub(crate) fn cordon_patch() -> serde_json::Value {
    serde_json::json!({ "spec": { "unschedulable": true } })
}

/// Explicit `false` clears the scheduling hold in a merge patch.
pub(crate) fn uncordon_patch() -> serde_json::Value {
    serde_json::json!({ "spec": { "unschedulable": false } })
}

/// Excludes DaemonSet and static mirror pods, which eviction cannot clear.
pub(crate) fn drainable(pod: &Pod) -> bool {
    if pod
        .metadata
        .annotations
        .as_ref()
        .is_some_and(|annotations| annotations.contains_key("kubernetes.io/config.mirror"))
    {
        return false;
    }
    !pod.metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| owners.iter().any(|owner| owner.kind == "DaemonSet"))
}

/// True when the pod reached a terminal phase; such pods hold no
/// running workload, so drain retires them with a direct delete instead
/// of asking a scheduler for eviction it cannot serve.
pub(crate) fn terminal(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|status| status.phase.as_deref())
        .is_some_and(|phase| matches!(phase, "Succeeded" | "Failed"))
}

/// Sort and deduplicate the drain work list.
pub(crate) fn drain_targets(pods: &[Pod]) -> Vec<String> {
    let mut names: Vec<String> = pods
        .iter()
        .filter(|pod| drainable(pod))
        .filter_map(|pod| pod.metadata.name.clone())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Unprocessed targets are reported as remaining when the deadline expires.
pub(crate) fn fold_deadline_remained(targets: &[String], from: usize) -> Vec<String> {
    targets[from.min(targets.len())..].to_vec()
}

/// A successful patch must also report the node as unschedulable.
pub async fn cordon(client: &KubeClient, node_name: &str) -> Result<(), KubeError> {
    let api: Api<Node> = Api::all(client.client.clone());
    let node = tokio::time::timeout(
        client.config.request_timeout,
        api.patch(
            node_name,
            &PatchParams::default(),
            &Patch::Merge(cordon_patch()),
        ),
    )
    .await
    .map_err(|_| KubeError::unavailable(format!("cordon of node {node_name} timed out")))??;
    cordon_landed(&node, node_name)
}

/// The API server's post-patch node must say unschedulable.
pub(crate) fn cordon_landed(node: &Node, node_name: &str) -> Result<(), KubeError> {
    if node.spec.as_ref().and_then(|spec| spec.unschedulable) != Some(true) {
        return Err(KubeError::unavailable(format!(
            "node {node_name} is still schedulable after the cordon patch"
        )));
    }
    Ok(())
}

/// Clears one node's unschedulable flag, then re-reads the node from the
/// API server so the caller learns the real post-patch schedulable state
/// instead of assuming the patch landed.
pub async fn uncordon(client: &KubeClient, node_name: &str) -> Result<bool, KubeError> {
    let api: Api<Node> = Api::all(client.client.clone());
    tokio::time::timeout(
        client.config.request_timeout,
        api.patch(
            node_name,
            &PatchParams::default(),
            &Patch::Merge(uncordon_patch()),
        ),
    )
    .await
    .map_err(|_| KubeError::unavailable(format!("uncordon of node {node_name} timed out")))??;
    schedulable(client, node_name).await
}

/// The node's real current schedulable state, read from the API server:
/// `false` exactly when `spec.unschedulable` holds.
pub async fn schedulable(client: &KubeClient, node_name: &str) -> Result<bool, KubeError> {
    let api: Api<Node> = Api::all(client.client.clone());
    let node = tokio::time::timeout(client.config.request_timeout, api.get(node_name))
        .await
        .map_err(|_| KubeError::unavailable(format!("node {node_name} observation timed out")))??;
    Ok(!node
        .spec
        .as_ref()
        .is_some_and(|spec| spec.unschedulable == Some(true)))
}

/// `false` means the pod is absent; API failures remain errors.
async fn present(api: &Api<Pod>, name: &str, bound: Duration) -> Result<bool, KubeError> {
    let probe = async {
        match api.get_opt(name).await {
            Ok(found) => Ok(found.is_some()),
            Err(kube::Error::Api(status)) if status.code == 404 => Ok(false),
            Err(error) => Err(KubeError::from(error)),
        }
    };
    tokio::time::timeout(bound, probe)
        .await
        .map_err(|_| KubeError::unavailable(format!("pod {name} observation timed out")))?
}

/// Lists the node's pods in one bounded, fail-closed scan.
async fn pods_on_node(client: &KubeClient, node_name: &str) -> Result<Vec<Pod>, KubeError> {
    let api: Api<Pod> = Api::all(client.client.clone());
    let pods = tokio::time::timeout(
        client.config.request_timeout,
        api.list(
            &ListParams::default()
                .fields(&format!("spec.nodeName={node_name}"))
                .limit(POD_SCAN_LIMIT),
        ),
    )
    .await
    .map_err(|_| KubeError::unavailable(format!("node {node_name} pod scan timed out")))??;
    if pods
        .metadata
        .continue_
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(KubeError::unavailable(format!(
            "node {node_name} pod inventory exceeds the bounded drain scan"
        )));
    }
    Ok(pods.items)
}

/// The typed outcome of one bounded removal attempt. `Accepted` means the
/// API server took the eviction or delete; `Gone` means the pod was
/// already absent; `Refused` carries the server's refusal reason — the pod
/// stays put and the drain reports it, never retrying into a hang.
#[derive(Clone, Debug, Eq, PartialEq)]
enum EvictOutcome {
    Accepted,
    Gone,
    Refused(String),
}

/// Terminal pods use direct deletion; other pods use eviction so disruption
/// budgets apply. API refusals are reported, not bypassed by deletion.
async fn evict_once(
    api: &Api<Pod>,
    name: &str,
    direct: bool,
    bound: Duration,
) -> Result<EvictOutcome, KubeError> {
    let attempt = async {
        if direct {
            return match api.delete(name, &DeleteParams::default()).await {
                Ok(_) => Ok(EvictOutcome::Accepted),
                Err(kube::Error::Api(status)) if status.code == 404 => Ok(EvictOutcome::Gone),
                Err(error) => Err(KubeError::from(error)),
            };
        }
        match api.evict(name, &EvictParams::default()).await {
            Ok(_) => Ok(EvictOutcome::Accepted),
            Err(kube::Error::Api(status)) if status.code == 404 => Ok(EvictOutcome::Gone),
            Err(kube::Error::Api(status)) => Ok(EvictOutcome::Refused(format!(
                "{} {} ({})",
                status.code, status.reason, status.message
            ))),
            Err(error) => Err(KubeError::from(error)),
        }
    };
    tokio::time::timeout(bound, attempt)
        .await
        .map_err(|_| KubeError::unavailable(format!("pod {name} removal timed out")))?
}

/// Cordons before eviction. Refused evictions and pods still present at the
/// deadline are returned in [`DrainReport::remained`] rather than as errors.
pub async fn drain(
    client: &KubeClient,
    node_name: &str,
    deadline: Duration,
) -> Result<DrainReport, KubeError> {
    let started = tokio::time::Instant::now();
    cordon(client, node_name).await?;
    let pods = pods_on_node(client, node_name).await?;
    let targets = drain_targets(&pods);
    let mut report = DrainReport {
        node: node_name.to_owned(),
        cordoned: true,
        evicted: Vec::new(),
        remained: Vec::new(),
    };
    for (index, name) in targets.iter().enumerate() {
        let elapsed = started.elapsed();
        if elapsed >= deadline {
            report
                .remained
                .extend(fold_deadline_remained(&targets, index));
            return Ok(report);
        }
        let pod = pods
            .iter()
            .find(|pod| pod.metadata.name.as_deref() == Some(name.as_str()));
        // Pods are namespaced objects; a listing without a namespace is
        // not addressable, so it is reported rather than fabricated at.
        let namespace = pod.and_then(|pod| pod.metadata.namespace.clone());
        let scoped = match namespace.as_deref() {
            Some(namespace) => Api::namespaced(client.client.clone(), namespace),
            None => {
                report.remained.push(name.clone());
                continue;
            }
        };
        let direct = pod.is_some_and(terminal);
        match evict_once(&scoped, name, direct, client.config.request_timeout).await? {
            EvictOutcome::Gone => report.evicted.push(name.clone()),
            EvictOutcome::Refused(_) => report.remained.push(name.clone()),
            EvictOutcome::Accepted => {
                let gone = wait_absent(
                    &scoped,
                    name,
                    deadline.saturating_sub(started.elapsed()),
                    client.config.request_timeout,
                )
                .await?;
                if gone {
                    report.evicted.push(name.clone());
                } else {
                    report.remained.push(name.clone());
                }
            }
        }
    }
    Ok(report)
}

/// Returns false if the pod remains at `bound`; each probe uses `request_bound`.
async fn wait_absent(
    api: &Api<Pod>,
    name: &str,
    bound: Duration,
    request_bound: Duration,
) -> Result<bool, KubeError> {
    let waited = tokio::time::Instant::now();
    loop {
        if !present(api, name, request_bound).await? {
            return Ok(true);
        }
        if waited.elapsed() >= bound {
            return Ok(false);
        }
        tokio::time::sleep(ABSENCE_POLL.min(bound.saturating_sub(waited.elapsed()))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{PodSpec, PodStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};

    #[test]
    fn a_cordon_the_server_did_not_apply_is_an_error() {
        let node = |unschedulable: Option<bool>| Node {
            spec: Some(k8s_openapi::api::core::v1::NodeSpec {
                unschedulable,
                ..Default::default()
            }),
            ..Default::default()
        };
        cordon_landed(&node(Some(true)), "pc").expect("cordoned");
        assert!(cordon_landed(&node(None), "pc").is_err());
        assert!(cordon_landed(&node(Some(false)), "pc").is_err());
    }

    fn pod(name: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                ..ObjectMeta::default()
            },
            spec: Some(PodSpec::default()),
            status: Some(PodStatus::default()),
        }
    }

    fn owned(mut pod: Pod, kind: &str) -> Pod {
        pod.metadata.owner_references = Some(vec![OwnerReference {
            api_version: "apps/v1".to_owned(),
            kind: kind.to_owned(),
            name: "controller".to_owned(),
            uid: "uid".to_owned(),
            controller: Some(true),
            block_owner_deletion: None,
        }]);
        pod
    }

    #[test]
    fn cordon_and_uncordon_patches_express_the_scheduler_law() {
        assert_eq!(
            cordon_patch(),
            serde_json::json!({ "spec": { "unschedulable": true } })
        );
        assert_eq!(
            uncordon_patch(),
            serde_json::json!({ "spec": { "unschedulable": false } })
        );
    }

    #[test]
    fn daemonset_owned_and_mirror_pods_are_not_drainable() {
        assert!(drainable(&pod("worker")));
        assert!(!drainable(&owned(pod("node-service"), "DaemonSet")));
        assert!(drainable(&owned(pod("replica"), "ReplicaSet")));

        let mut mirror = pod("mirror");
        mirror.metadata.annotations = Some(
            [("kubernetes.io/config.mirror".to_owned(), "{}".to_owned())]
                .into_iter()
                .collect(),
        );
        assert!(!drainable(&mirror));
    }

    #[test]
    fn terminal_phase_pods_are_recognized_for_direct_removal() {
        let mut done = pod("done");
        done.status.as_mut().unwrap().phase = Some("Succeeded".to_owned());
        assert!(terminal(&done));
        let mut failed = pod("failed");
        failed.status.as_mut().unwrap().phase = Some("Failed".to_owned());
        assert!(terminal(&failed));
        let mut running = pod("running");
        running.status.as_mut().unwrap().phase = Some("Running".to_owned());
        assert!(!terminal(&running));
    }

    #[test]
    fn drain_targets_are_sorted_deduplicated_and_skip_undrainable_pods() {
        let pods = vec![
            owned(pod("svclb-x"), "DaemonSet"),
            pod("zeta"),
            pod("alpha"),
            pod("alpha"),
            {
                let mut mirror = pod("mirror-pod");
                mirror.metadata.annotations = Some(
                    [("kubernetes.io/config.mirror".to_owned(), "{}".to_owned())]
                        .into_iter()
                        .collect(),
                );
                mirror
            },
        ];
        assert_eq!(
            drain_targets(&pods),
            vec!["alpha".to_owned(), "zeta".to_owned()]
        );
        assert!(drain_targets(&[]).is_empty());
    }

    #[test]
    fn the_deadline_folds_every_unproven_pod_into_remained_in_order() {
        let targets = vec!["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()];
        // Include the current pod and every unprocessed target at the deadline.
        assert_eq!(
            fold_deadline_remained(&targets, 1),
            ["beta".to_owned(), "gamma".to_owned()]
        );
        // A deadline hit after the last pod: nothing remained.
        assert!(fold_deadline_remained(&targets, 3).is_empty());
        // An index past the work list's end folds nothing (defensive).
        assert!(fold_deadline_remained(&targets, 99).is_empty());
    }
}
