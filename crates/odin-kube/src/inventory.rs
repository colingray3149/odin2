//! Bounded Pod inventory for the compute overview.
//!
//! Rows are Pods, keyed by `spec.nodeName`. A Job is not a pod: a Job with
//! several pods is several rows, and a Deployment or DaemonSet pod is a row
//! even when no Job owns it. Unscheduled pods have no node and are omitted.

use std::time::Duration;

use k8s_openapi::api::core::v1::Pod;
use kube::api::ListParams;

use crate::client::{KubeClient, KubeError};

/// One page. A cluster with more pods reports truncation instead of walking
/// every continue token into memory.
pub const POD_INVENTORY_LIMIT: u32 = 256;
const LIST_BOUND: Duration = Duration::from_secs(3);

/// One pod actually scheduled onto a node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedPod {
    pub name: String,
    pub node: String,
    pub phase: String,
}

/// One bounded listing. `truncated` means the API had another page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodInventory {
    pub pods: Vec<ObservedPod>,
    pub truncated: bool,
}

/// List pods across every namespace, one bounded page, keyed by the node
/// the scheduler wrote. A down API is an error, not an empty cluster.
pub async fn list_pods(client: &KubeClient) -> Result<PodInventory, KubeError> {
    let api: kube::Api<Pod> = kube::Api::all(client.client.clone());
    let page = tokio::time::timeout(
        LIST_BOUND.min(client.config.request_timeout),
        api.list(&ListParams::default().limit(POD_INVENTORY_LIMIT)),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("pod inventory timed out: {error}")))?
    .map_err(|error| KubeError::unavailable(format!("pod inventory failed: {error}")))?;
    let truncated = page
        .metadata
        .continue_
        .as_deref()
        .is_some_and(|token| !token.is_empty());
    let mut pods = page
        .items
        .into_iter()
        .filter_map(observe_pod)
        .collect::<Vec<_>>();
    pods.sort_by(|left, right| left.node.cmp(&right.node).then(left.name.cmp(&right.name)));
    pods.truncate(POD_INVENTORY_LIMIT as usize);
    Ok(PodInventory { pods, truncated })
}

/// A scheduled pod keeps its own name and phase. No `nodeName` means it is
/// not on a node yet. A deleting pod is `terminating`, not its last phase.
pub fn observe_pod(pod: Pod) -> Option<ObservedPod> {
    let name = pod.metadata.name.filter(|name| !name.is_empty())?;
    let node = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.node_name.clone())
        .filter(|node| !node.is_empty())?;
    let phase = if pod.metadata.deletion_timestamp.is_some() {
        "terminating".to_owned()
    } else {
        pod.status
            .as_ref()
            .and_then(|status| status.phase.clone())
            .filter(|phase| !phase.is_empty())
            .unwrap_or_else(|| "unknown".to_owned())
            .to_ascii_lowercase()
    };
    Some(ObservedPod { name, node, phase })
}
