use super::*;
use k8s_openapi::api::core::v1::{NodeSelectorRequirement, NodeSelectorTerm};

/// The run's claim and volume, plus hostname values reported from volume affinity.
/// `admitted_nodes` is `None` if the claim is unbound or its volume is missing.
/// An empty list means no recognized hostname constraints, not a placement decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadStateBinding {
    pub claim: String,
    pub bound_volume: Option<String>,
    pub admitted_nodes: Option<Vec<String>>,
}

/// Read-only; `Ok(None)` means the run has no state claim.
pub async fn state_binding(
    client: &KubeClient,
    run_id: &RunId,
) -> Result<Option<WorkloadStateBinding>, KubeError> {
    let claim = match client
        .persistent_volume_claims()
        .get_opt(&state_claim_name(run_id))
        .await
    {
        Ok(Some(claim)) => claim,
        Ok(None) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let bound_volume = claim
        .spec
        .as_ref()
        .and_then(|spec| spec.volume_name.clone());
    let admitted_nodes = match &bound_volume {
        Some(volume) => match client.persistent_volumes().get_opt(volume).await {
            Ok(Some(pv)) => Some(pv_admitted_nodes(&pv)),
            Ok(None) => None,
            Err(error) => return Err(error.into()),
        },
        None => None,
    };
    Ok(Some(WorkloadStateBinding {
        claim: state_claim_name(run_id),
        bound_volume,
        admitted_nodes,
    }))
}

/// Reports hostname/name `In` values only; use [`pv_admits_node_labels`] for admission.
pub fn pv_admitted_nodes(pv: &PersistentVolume) -> Vec<String> {
    let Some(required) = pv
        .spec
        .as_ref()
        .and_then(|spec| spec.node_affinity.as_ref())
        .and_then(|affinity| affinity.required.as_ref())
    else {
        return vec![];
    };
    let mut admitted = BTreeSet::new();
    for requirement in required
        .node_selector_terms
        .iter()
        .flat_map(term_requirements)
    {
        let hostname_key =
            requirement.key == "kubernetes.io/hostname" && requirement.operator == "In";
        let name_key = requirement.key == "metadata.name" && requirement.operator == "In";
        if hostname_key || name_key {
            admitted.extend(requirement.values.iter().flatten().cloned());
        }
    }
    admitted.into_iter().collect()
}

fn term_requirements(term: &NodeSelectorTerm) -> impl Iterator<Item = &NodeSelectorRequirement> {
    term.match_expressions
        .iter()
        .flatten()
        .chain(term.match_fields.iter().flatten())
}

/// `None` means the requirement cannot be evaluated and its term must not match.
fn requirement_admits(
    requirement: &NodeSelectorRequirement,
    node_name: &str,
    node_labels: &BTreeMap<String, String>,
) -> Option<bool> {
    match requirement.operator.as_str() {
        "In" | "NotIn" => {
            let values = requirement.values.as_ref()?;
            let observed: Option<&str> = if requirement.key == "metadata.name" {
                Some(node_name)
            } else {
                node_labels.get(&requirement.key).map(String::as_str)
            };
            let contained =
                observed.is_some_and(|value| values.iter().any(|candidate| candidate == value));
            let matched = if requirement.operator == "In" {
                contained
            } else {
                !contained
            };
            Some(matched)
        }
        "Exists" => Some(node_labels.contains_key(&requirement.key)),
        "DoesNotExist" => Some(!node_labels.contains_key(&requirement.key)),
        // Gt/Lt and unknown operators are unsupported.
        _ => None,
    }
}

/// A target must satisfy every requirement in at least one affinity term.
/// No required affinity allows all nodes; unsupported requirements fail their term.
pub fn pv_admits_node_labels(
    pv: &PersistentVolume,
    node_name: &str,
    node_labels: &BTreeMap<String, String>,
) -> Result<(), String> {
    let Some(required) = pv
        .spec
        .as_ref()
        .and_then(|spec| spec.node_affinity.as_ref())
        .and_then(|affinity| affinity.required.as_ref())
    else {
        // No required affinity: unrestricted (shared) storage.
        return Ok(());
    };
    if required.node_selector_terms.is_empty() {
        return Err(
            "state volume carries an empty node selector; no target can be proven admitted"
                .to_owned(),
        );
    }
    let mut unsupported = None;
    for term in &required.node_selector_terms {
        let mut proven = true;
        for requirement in term_requirements(term) {
            match requirement_admits(requirement, node_name, node_labels) {
                Some(true) => {}
                Some(false) => {
                    proven = false;
                    break;
                }
                // An operator this check cannot evaluate keeps its term from matching.
                None => {
                    unsupported.get_or_insert(requirement.operator.as_str());
                    proven = false;
                    break;
                }
            }
        }
        if proven {
            return Ok(());
        }
    }
    Err(match unsupported {
        Some(operator) => format!(
            "state volume's node affinity uses the operator {operator:?}, which rehome admission \
             cannot evaluate; node {node_name:?} is not proven to admit it"
        ),
        None => format!(
            "state volume's node affinity admits none of its terms for node {node_name:?}; \
             rehome would strand per-pod state"
        ),
    })
}

/// Check volume affinity against the target node before stopping the workload.
/// Unbound claims remain schedulable; unreadable nodes or volumes return an error.
pub async fn verify_state_admits_node(
    client: &KubeClient,
    run_id: &RunId,
    plan: &WorkloadPodPlan,
    node: &str,
) -> Result<(), KubeError> {
    let claim = require_state_claim(client, run_id, plan).await?;
    let Some(volume) = claim
        .spec
        .as_ref()
        .and_then(|spec| spec.volume_name.clone())
    else {
        // The scheduler can still place an unbound claim on the target.
        return Ok(());
    };
    let pv = client
        .persistent_volumes()
        .get_opt(&volume)
        .await
        .map_err(Into::<KubeError>::into)?
        .ok_or_else(|| {
            KubeError::unavailable(format!(
                "state claim is bound to volume {volume} but the volume is not readable"
            ))
        })?;
    let node_api: kube::Api<k8s_openapi::api::core::v1::Node> =
        kube::Api::all(client.client.clone());
    let target = tokio::time::timeout(client.request_timeout(), node_api.get_opt(node))
        .await
        .map_err(|error| {
            KubeError::unavailable(format!("rehome target node query timed out: {error}"))
        })?
        .map_err(Into::<KubeError>::into)?
        .ok_or_else(|| {
            KubeError::rejected(format!(
                "rehome target node {node:?} does not exist in the cluster"
            ))
        })?;
    let labels = target.metadata.labels.clone().unwrap_or_default();
    pv_admits_node_labels(&pv, node, &labels).map_err(KubeError::rejected)
}

/// Pod placement supplies the node needed for browser attach; Job status has no node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadPlacement {
    pub pod: String,
    pub node: Option<String>,
    pub phase: Option<String>,
    pub timeline: crate::pod_phase::PodTimeline,
}

/// Ignore terminating and terminal pods; reject multiple live candidates rather
/// than guessing an attach address. `Ok(None)` means no live pod was found.
pub async fn placement(
    client: &KubeClient,
    run_id: &RunId,
) -> Result<Option<WorkloadPlacement>, KubeError> {
    let selector = run_claim_labels(run_id)
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    let pods = tokio::time::timeout(
        client.request_timeout(),
        client.pods().list(&ListParams::default().labels(&selector)),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("workload pod query timed out: {error}")))?
    .map_err(KubeError::from)?;
    let carrying = |pod: &Pod| {
        let phase = pod
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref());
        pod.metadata.deletion_timestamp.is_none()
            && !matches!(phase, Some("Failed") | Some("Succeeded"))
    };
    let live: Vec<&Pod> = pods.items.iter().filter(|pod| carrying(pod)).collect();
    match live.as_slice() {
        [] => Ok(None),
        [pod] => {
            let name = pod.metadata.name.clone().ok_or_else(|| {
                KubeError::rejected("a bound carrier pod carries no metadata name")
            })?;
            Ok(Some(WorkloadPlacement {
                pod: name,
                node: pod.spec.as_ref().and_then(|spec| spec.node_name.clone()),
                phase: pod.status.as_ref().and_then(|status| status.phase.clone()),
                timeline: crate::pod_phase::PodTimeline::of(pod),
            }))
        }
        [..] => Err(KubeError::rejected(format!(
            "run carries {} live carrier pods under one binding label; the attach address is ambiguous",
            live.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_api::ScriptedApi;
    use serde_json::{json, Value};

    fn pod(name: &str, node: &str, phase: &str, terminating: bool) -> Value {
        let mut metadata = json!({"name": name});
        if terminating {
            metadata["deletionTimestamp"] = json!("2026-11-01T00:00:00Z");
        }
        json!({"metadata": metadata, "spec": {"containers": [], "nodeName": node},
            "status": {"phase": phase}})
    }

    async fn placement_of(pods: Vec<Value>) -> Result<Option<WorkloadPlacement>, KubeError> {
        let api = ScriptedApi::start(vec![
            json!({"apiVersion": "v1", "kind": "PodList", "metadata": {}, "items": pods})
                .to_string(),
        ])
        .await;
        placement(&api.client(), &RunId::new("placement-law").expect("run id")).await
    }

    #[tokio::test]
    async fn placement_names_the_one_live_carrier_and_refuses_to_guess_between_two() {
        let found = placement_of(vec![
            pod("old", "pc", "Succeeded", false),
            pod("dying", "pc", "Running", true),
            pod("live", "mini", "Running", false),
        ])
        .await
        .expect("placement")
        .expect("a live carrier");
        assert_eq!(
            (found.pod.as_str(), found.node.as_deref()),
            ("live", Some("mini"))
        );

        assert_eq!(
            placement_of(vec![pod("old", "pc", "Failed", false)])
                .await
                .expect("placement"),
            None
        );
        let error = placement_of(vec![
            pod("one", "mini", "Running", false),
            pod("two", "pc", "Pending", false),
        ])
        .await
        .expect_err("two live carriers");
        assert!(matches!(error, KubeError::Rejected { .. }), "{error:?}");
    }
}
