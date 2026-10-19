//! Placement from schedulable node capabilities and observed resource reservations.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Container, Node, Pod, PodSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::api::ListParams;
use odin_domain::{huginn::KubeResourceRef, NodeId};

use crate::client::{KubeClient, KubeError};

pub use odin_domain::huginn::{KubeNodeState, KubeNodeView, KubeResources};

/// Rechecks published placement admission before creating or rehoming a Job.
pub(crate) fn require_placement_authority(
    allowed_nodes: &std::collections::BTreeSet<String>,
    target: Option<&str>,
) -> Result<(), KubeError> {
    if allowed_nodes.is_empty() {
        return Err(KubeError::rejected(
            "the published registry admits no workload nodes",
        ));
    }
    if target.is_some_and(|node| !allowed_nodes.contains(node)) {
        return Err(KubeError::rejected(
            "the target node is not admitted for workloads",
        ));
    }
    Ok(())
}

/// Returns a node name for required node affinity. The caller must retain scheduler
/// admission, rather than bypassing resource checks through `PodSpec.node_name`.
pub async fn choose_node(
    client: &KubeClient,
    required_labels: &BTreeMap<String, String>,
    request: KubeResources,
    target: Option<&str>,
) -> Result<String, KubeError> {
    let node_api: kube::Api<Node> = kube::Api::all(client.client.clone());
    let pod_api: kube::Api<Pod> = kube::Api::all(client.client.clone());
    let nodes = tokio::time::timeout(
        client.config.request_timeout,
        node_api.list(&ListParams::default().limit(1024)),
    )
    .await
    .map_err(|_| KubeError::unavailable("node placement observation timed out"))??;
    let pods = tokio::time::timeout(
        client.config.request_timeout,
        pod_api.list(&ListParams::default().limit(4096)),
    )
    .await
    .map_err(|_| KubeError::unavailable("pod reservation observation timed out"))??;
    if nodes
        .metadata
        .continue_
        .as_ref()
        .is_some_and(|value| !value.is_empty())
        || pods
            .metadata
            .continue_
            .as_ref()
            .is_some_and(|value| !value.is_empty())
    {
        return Err(KubeError::unavailable(
            "cluster inventory exceeds the bounded placement scan",
        ));
    }
    select_node(
        nodes.items,
        &pods.items,
        &client.config.allowed_nodes,
        required_labels,
        request,
        target,
    )
}

fn select_node(
    mut candidates: Vec<Node>,
    pods: &[Pod],
    allowed_nodes: &std::collections::BTreeSet<String>,
    required_labels: &BTreeMap<String, String>,
    request: KubeResources,
    target: Option<&str>,
) -> Result<String, KubeError> {
    require_placement_authority(allowed_nodes, target)?;
    let mut reservations: BTreeMap<String, (KubeResources, u64)> = BTreeMap::new();
    for pod in pods {
        if pod
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            .is_some_and(|phase| matches!(phase, "Succeeded" | "Failed"))
        {
            continue;
        }
        if let Some(spec) = &pod.spec {
            if let Some(node) = &spec.node_name {
                let reservation = reservations.entry(node.clone()).or_default();
                add(&mut reservation.0, &pod_reservation(pod, spec)?)?;
                reservation.1 = reservation.1.checked_add(1).ok_or_else(arithmetic_error)?;
            }
        }
    }
    candidates.sort_unstable_by(|left, right| left.metadata.name.cmp(&right.metadata.name));
    for node in candidates {
        let Some(name) = node.metadata.name.as_deref() else {
            continue;
        };
        if !allowed_nodes.contains(name)
            || target.is_some_and(|target| target != name)
            || !schedulable(&node)
        {
            continue;
        }
        if !required_labels.iter().all(|(key, value)| {
            node.metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(key))
                == Some(value)
        }) {
            continue;
        }
        let allocatable = resource_requirements(
            node.status
                .as_ref()
                .and_then(|status| status.allocatable.as_ref()),
        )?;
        let (reserved, pod_count) = reservations.get(name).copied().unwrap_or_default();
        let slots = node
            .status
            .as_ref()
            .and_then(|status| status.allocatable.as_ref())
            .and_then(|values| values.get("pods"))
            .map_or(Ok(0), |value| quantity_units(&value.0, 1))?;
        if pod_count < slots && fits(request, allocatable, reserved) {
            return Ok(name.to_owned());
        }
    }
    Err(KubeError::unavailable(
        "no ready schedulable node satisfies the Job capabilities and resource reservations",
    ))
}

/// The read-only view of one node object; `revision` is the caller's
/// ordinal (the catalog stamps the durable one).
pub fn node_view(cluster: &str, node: &Node, revision: u64) -> Result<KubeNodeView, KubeError> {
    let name = node.metadata.name.as_ref().ok_or_else(arithmetic_error)?;
    let uid = node.metadata.uid.as_ref().ok_or_else(arithmetic_error)?;
    let facts = node_facts(node)?;
    Ok(KubeNodeView {
        node_id: NodeId::new(name)
            .map_err(|_| KubeError::rejected("node name has no valid Odin identity"))?,
        resource: KubeResourceRef {
            cluster: cluster.to_owned(),
            api_version: "v1".to_owned(),
            kind: "Node".to_owned(),
            namespace: None,
            name: name.clone(),
            uid: uid.clone(),
        },
        revision,
        state: facts.state,
        architecture: facts.architecture,
        operating_system: facts.operating_system,
        capacity: facts.capacity,
        allocatable: facts.allocatable,
        usage: KubeResources::default(),
        // No metrics server: node usage is unobserved, never a measured
        // zero.
        usage_stale: true,
        observed_at: time::OffsetDateTime::now_utc(),
        stale: false,
    })
}

pub(crate) struct NodeFacts {
    pub state: KubeNodeState,
    pub unschedulable: bool,
    pub architecture: String,
    pub operating_system: String,
    pub capacity: KubeResources,
    pub allocatable: KubeResources,
}

/// `Unschedulable` spec wins, then the `Ready` condition, else `Unknown`.
pub(crate) fn node_facts(node: &Node) -> Result<NodeFacts, KubeError> {
    let status = node.status.as_ref();
    let unschedulable = node
        .spec
        .as_ref()
        .is_some_and(|spec| spec.unschedulable == Some(true));
    let ready = status
        .and_then(|status| status.conditions.as_ref())
        .and_then(|conditions| {
            conditions
                .iter()
                .find(|condition| condition.type_ == "Ready")
        })
        .map(|condition| condition.status.as_str());
    let state = if unschedulable {
        KubeNodeState::Unschedulable
    } else {
        match ready {
            Some("True") => KubeNodeState::Ready,
            Some("False") => KubeNodeState::NotReady,
            _ => KubeNodeState::Unknown,
        }
    };
    let info = status.and_then(|status| status.node_info.as_ref());
    Ok(NodeFacts {
        state,
        unschedulable,
        architecture: info
            .map(|info| info.architecture.clone())
            .unwrap_or_default(),
        operating_system: info
            .map(|info| info.operating_system.clone())
            .unwrap_or_default(),
        capacity: resource_requirements(status.and_then(|status| status.capacity.as_ref()))?,
        allocatable: resource_requirements(status.and_then(|status| status.allocatable.as_ref()))?,
    })
}

fn schedulable(node: &Node) -> bool {
    if node.metadata.deletion_timestamp.is_some()
        || node.spec.as_ref().is_some_and(|spec| {
            spec.unschedulable == Some(true)
                || spec.taints.as_ref().is_some_and(|taints| {
                    taints
                        .iter()
                        .any(|taint| matches!(taint.effect.as_str(), "NoSchedule" | "NoExecute"))
                })
        })
    {
        return false;
    }
    node.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        })
}

fn fits(request: KubeResources, capacity: KubeResources, used: KubeResources) -> bool {
    request.cpu_millis <= capacity.cpu_millis.saturating_sub(used.cpu_millis)
        && request.memory_bytes <= capacity.memory_bytes.saturating_sub(used.memory_bytes)
        && request.ephemeral_storage_bytes
            <= capacity
                .ephemeral_storage_bytes
                .saturating_sub(used.ephemeral_storage_bytes)
        && request.gpu_count <= capacity.gpu_count.saturating_sub(used.gpu_count)
}

pub(crate) fn resource_requirements(
    values: Option<&BTreeMap<String, Quantity>>,
) -> Result<KubeResources, KubeError> {
    resource_values(|name| values.and_then(|values| values.get(name)))
}

fn resource_values<'a>(
    get: impl Fn(&str) -> Option<&'a Quantity>,
) -> Result<KubeResources, KubeError> {
    let value =
        |name, scale| get(name).map_or(Ok(0), |quantity| quantity_units(&quantity.0, scale));
    Ok(KubeResources {
        cpu_millis: value("cpu", 1000)?,
        memory_bytes: value("memory", 1)?,
        ephemeral_storage_bytes: value("ephemeral-storage", 1)?,
        gpu_count: u32::try_from(value("nvidia.com/gpu", 1)?).map_err(|_| arithmetic_error())?,
    })
}

pub(crate) fn container_resources(
    container: &Container,
) -> Result<(KubeResources, KubeResources), KubeError> {
    let resources = container.resources.as_ref();
    let limits = resources.and_then(|resources| resources.limits.as_ref());
    let requests = resources.and_then(|resources| resources.requests.as_ref());
    let requested = resource_values(|name| {
        requests
            .and_then(|values| values.get(name))
            .or_else(|| limits.and_then(|values| values.get(name)))
    })?;
    Ok((requested, resource_requirements(limits)?))
}

pub(crate) fn pod_requests(spec: &PodSpec) -> Result<KubeResources, KubeError> {
    pod_resources(spec, false)
}

pub(crate) fn pod_limits(spec: &PodSpec) -> Result<KubeResources, KubeError> {
    pod_resources(spec, true)
}

fn pod_resources(spec: &PodSpec, limits: bool) -> Result<KubeResources, KubeError> {
    let select = |container: &Container| {
        container_resources(container)
            .map(|(requests, ceiling)| if limits { ceiling } else { requests })
    };
    let regular = aggregate_containers(spec, select)?;
    apply_pod_resources(spec, regular, limits)
}

fn pod_reservation(pod: &Pod, spec: &PodSpec) -> Result<KubeResources, KubeError> {
    let actual = aggregate_containers(spec, |container| {
        let (mut requested, _) = container_resources(container)?;
        if let Some(status) = pod.status.as_ref().and_then(|status| {
            status
                .container_statuses
                .iter()
                .flatten()
                .chain(status.init_container_statuses.iter().flatten())
                .find(|status| status.name == container.name)
        }) {
            maximum(
                &mut requested,
                &resource_requirements(status.allocated_resources.as_ref())?,
            );
            maximum(
                &mut requested,
                &resource_requirements(
                    status
                        .resources
                        .as_ref()
                        .and_then(|resources| resources.requests.as_ref()),
                )?,
            );
        }
        Ok(requested)
    })?;
    let mut requested = pod_requests(spec)?;
    let mut actual = actual;
    add(&mut actual, &resource_requirements(spec.overhead.as_ref())?)?;
    maximum(&mut requested, &actual);
    Ok(requested)
}

fn aggregate_containers(
    spec: &PodSpec,
    select: impl Fn(&Container) -> Result<KubeResources, KubeError>,
) -> Result<KubeResources, KubeError> {
    let mut regular = KubeResources::default();
    for container in &spec.containers {
        add(&mut regular, &select(container)?)?;
    }
    let mut sidecars = KubeResources::default();
    let mut initialization_peak = KubeResources::default();
    for container in spec.init_containers.iter().flatten() {
        let resources = select(container)?;
        let mut concurrent = sidecars;
        add(&mut concurrent, &resources)?;
        if container.restart_policy.as_deref() == Some("Always") {
            sidecars = concurrent;
        }
        maximum(&mut initialization_peak, &concurrent);
    }
    add(&mut regular, &sidecars)?;
    maximum(&mut regular, &initialization_peak);
    Ok(regular)
}

fn apply_pod_resources(
    spec: &PodSpec,
    mut regular: KubeResources,
    limits: bool,
) -> Result<KubeResources, KubeError> {
    if let Some(resources) = &spec.resources {
        let primary = if limits {
            resources.limits.as_ref()
        } else {
            resources.requests.as_ref()
        };
        let get = |name| {
            primary.and_then(|values| values.get(name)).or_else(|| {
                if limits {
                    None
                } else {
                    resources
                        .limits
                        .as_ref()
                        .and_then(|values| values.get(name))
                }
            })
        };
        if let Some(cpu) = get("cpu") {
            regular.cpu_millis = quantity_units(&cpu.0, 1000)?;
        }
        if let Some(memory) = get("memory") {
            regular.memory_bytes = quantity_units(&memory.0, 1)?;
        }
    }
    let mut overhead = resource_requirements(spec.overhead.as_ref())?;
    if limits {
        if regular.cpu_millis == 0 {
            overhead.cpu_millis = 0;
        }
        if regular.memory_bytes == 0 {
            overhead.memory_bytes = 0;
        }
        if regular.ephemeral_storage_bytes == 0 {
            overhead.ephemeral_storage_bytes = 0;
        }
        if regular.gpu_count == 0 {
            overhead.gpu_count = 0;
        }
    }
    add(&mut regular, &overhead)?;
    Ok(regular)
}

fn add(total: &mut KubeResources, value: &KubeResources) -> Result<(), KubeError> {
    total.cpu_millis = total
        .cpu_millis
        .checked_add(value.cpu_millis)
        .ok_or_else(arithmetic_error)?;
    total.memory_bytes = total
        .memory_bytes
        .checked_add(value.memory_bytes)
        .ok_or_else(arithmetic_error)?;
    total.ephemeral_storage_bytes = total
        .ephemeral_storage_bytes
        .checked_add(value.ephemeral_storage_bytes)
        .ok_or_else(arithmetic_error)?;
    total.gpu_count = total
        .gpu_count
        .checked_add(value.gpu_count)
        .ok_or_else(arithmetic_error)?;
    Ok(())
}

fn maximum(total: &mut KubeResources, value: &KubeResources) {
    total.cpu_millis = total.cpu_millis.max(value.cpu_millis);
    total.memory_bytes = total.memory_bytes.max(value.memory_bytes);
    total.ephemeral_storage_bytes = total
        .ephemeral_storage_bytes
        .max(value.ephemeral_storage_bytes);
    total.gpu_count = total.gpu_count.max(value.gpu_count);
}

/// Exact fixed-point conversion with upward rounding, matching Kubernetes scheduling
/// units. Overflow or unknown suffixes fail closed instead of undercounting requests.
fn quantity_units(raw: &str, scale: u128) -> Result<u64, KubeError> {
    let mut numeric = raw;
    let mut decimal_power = 0i32;
    let mut binary_factor = 1u128;
    for (suffix, exponent) in [
        ("Ki", 10),
        ("Mi", 20),
        ("Gi", 30),
        ("Ti", 40),
        ("Pi", 50),
        ("Ei", 60),
    ] {
        if let Some(prefix) = numeric.strip_suffix(suffix) {
            numeric = prefix;
            binary_factor = 1u128 << exponent;
            break;
        }
    }
    if binary_factor == 1 {
        for (suffix, exponent) in [
            ("n", -9),
            ("u", -6),
            ("m", -3),
            ("k", 3),
            ("K", 3),
            ("M", 6),
            ("G", 9),
            ("T", 12),
            ("P", 15),
            ("E", 18),
        ] {
            if let Some(prefix) = numeric.strip_suffix(suffix) {
                numeric = prefix;
                decimal_power = exponent;
                break;
            }
        }
    }
    if let Some(index) = numeric.find(['e', 'E']) {
        let exponent: i32 = numeric[index + 1..]
            .parse()
            .map_err(|_| arithmetic_error())?;
        decimal_power = decimal_power
            .checked_add(exponent)
            .ok_or_else(arithmetic_error)?;
        numeric = &numeric[..index];
    }
    numeric = numeric.strip_prefix('+').unwrap_or(numeric);
    let mut mantissa = 0u128;
    let mut fraction = false;
    let mut digits = 0usize;
    for byte in numeric.bytes() {
        if byte == b'.' && !fraction {
            fraction = true;
        } else if byte.is_ascii_digit() {
            mantissa = mantissa
                .checked_mul(10)
                .and_then(|value| value.checked_add(u128::from(byte - b'0')))
                .ok_or_else(arithmetic_error)?;
            digits += 1;
            if fraction {
                decimal_power = decimal_power.checked_sub(1).ok_or_else(arithmetic_error)?;
            }
        } else {
            return Err(arithmetic_error());
        }
    }
    if digits == 0 {
        return Err(arithmetic_error());
    }
    let mut numerator = mantissa
        .checked_mul(scale)
        .and_then(|value| value.checked_mul(binary_factor))
        .ok_or_else(arithmetic_error)?;
    let result = if decimal_power >= 0 {
        numerator = numerator
            .checked_mul(
                10u128
                    .checked_pow(decimal_power as u32)
                    .ok_or_else(arithmetic_error)?,
            )
            .ok_or_else(arithmetic_error)?;
        numerator
    } else {
        let denominator = 10u128
            .checked_pow(decimal_power.unsigned_abs())
            .ok_or_else(arithmetic_error)?;
        numerator / denominator + u128::from(numerator % denominator != 0)
    };
    u64::try_from(result).map_err(|_| arithmetic_error())
}

fn arithmetic_error() -> KubeError {
    KubeError::Rejected {
        reason: "Kubernetes resource quantity is invalid or exceeds bounded accounting".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ResourceRequirements;

    fn container(cpu: &str, sidecar: bool) -> Container {
        Container {
            name: "worker".to_owned(),
            resources: Some(ResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "cpu".to_owned(),
                    Quantity(cpu.to_owned()),
                )])),
                ..Default::default()
            }),
            restart_policy: sidecar.then(|| "Always".to_owned()),
            ..Default::default()
        }
    }

    fn placement_node(name: &str) -> Node {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": name,
                "labels": { "workload": "batch" }
            },
            "status": {
                "conditions": [{ "type": "Ready", "status": "True" }],
                "allocatable": {
                    "cpu": "4", "memory": "8Gi", "nvidia.com/gpu": "2",
                    "ephemeral-storage": "8Gi", "pods": "10"
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn fractional_requests_round_up_without_floating_point() {
        assert_eq!(quantity_units("250u", 1000).unwrap(), 1);
        assert_eq!(quantity_units("400m", 1).unwrap(), 1);
        assert_eq!(quantity_units("1.5Gi", 1).unwrap(), 1_610_612_736);
        assert_eq!(quantity_units("1e3", 1).unwrap(), 1000);
        assert!(quantity_units("-1", 1).is_err());
        assert!(quantity_units("1e100", 1).is_err());
    }

    #[test]
    fn sequential_init_peak_includes_running_sidecars_and_overhead() {
        let spec = PodSpec {
            containers: vec![container("200m", false), container("300m", false)],
            init_containers: Some(vec![
                container("100m", true),
                container("700m", false),
                container("200m", true),
            ]),
            overhead: Some(BTreeMap::from([(
                "cpu".to_owned(),
                Quantity("50m".to_owned()),
            )])),
            ..Default::default()
        };
        // Initialization peak 100+700 = 800; steady state 200+300+100+200 = 800.
        assert_eq!(pod_requests(&spec).unwrap().cpu_millis, 850);
    }

    #[test]
    fn observed_nodes_cannot_expand_declared_placement_authority() {
        let node = placement_node;
        let admitted = std::collections::BTreeSet::from(["worker-b".to_owned()]);
        let labels = BTreeMap::new();
        let request = KubeResources {
            cpu_millis: 1_000,
            ..KubeResources::default()
        };
        for inventory in [
            vec![node("worker-a"), node("worker-b")],
            vec![node("worker-b"), node("worker-a")],
        ] {
            assert_eq!(
                select_node(inventory, &[], &admitted, &labels, request, None).unwrap(),
                "worker-b",
            );
        }
        assert!(select_node(
            vec![node("worker-a"), node("worker-b")],
            &[],
            &admitted,
            &labels,
            request,
            Some("worker-a"),
        )
        .is_err());
        assert!(select_node(
            vec![node("worker-a")],
            &[],
            &Default::default(),
            &labels,
            request,
            None,
        )
        .is_err());
    }

    #[test]
    fn explicit_target_intersects_authority_and_preserves_declared_labels() {
        let admitted =
            std::collections::BTreeSet::from(["worker-a".to_owned(), "worker-b".to_owned()]);
        let labels = BTreeMap::from([("workload".to_owned(), "batch".to_owned())]);
        let declared_labels = labels.clone();
        let request = KubeResources {
            cpu_millis: 1_000,
            ..KubeResources::default()
        };
        let candidates = vec![placement_node("worker-a"), placement_node("worker-b")];
        assert_eq!(
            select_node(candidates.clone(), &[], &admitted, &labels, request, None).unwrap(),
            "worker-a",
        );
        assert_eq!(
            select_node(
                candidates.clone(),
                &[],
                &admitted,
                &labels,
                request,
                Some("worker-b"),
            )
            .unwrap(),
            "worker-b",
        );
        for allowed in [
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::from(["worker-a".to_owned()]),
        ] {
            assert!(select_node(
                candidates.clone(),
                &[],
                &allowed,
                &labels,
                request,
                Some("worker-b"),
            )
            .is_err());
        }
        for target_labels in [
            None,
            Some(BTreeMap::from([(
                "workload".to_owned(),
                "interactive".to_owned(),
            )])),
        ] {
            let mut target = placement_node("worker-b");
            target.metadata.labels = target_labels;
            let inventory = vec![placement_node("worker-a"), target];
            assert_eq!(
                select_node(inventory.clone(), &[], &admitted, &labels, request, None).unwrap(),
                "worker-a",
            );
            assert!(select_node(
                inventory,
                &[],
                &admitted,
                &labels,
                request,
                Some("worker-b"),
            )
            .is_err());
        }
        assert_eq!(labels, declared_labels);
    }

    #[test]
    fn explicit_target_never_falls_back_when_missing_or_unschedulable() {
        let admitted =
            std::collections::BTreeSet::from(["worker-a".to_owned(), "worker-b".to_owned()]);
        let labels = BTreeMap::from([("workload".to_owned(), "batch".to_owned())]);
        for (case, ready, cordoned, taint, deleting) in [
            ("missing", Some("True"), false, None, false),
            ("not ready", Some("False"), false, None, false),
            ("unknown readiness", Some("Unknown"), false, None, false),
            ("missing readiness", None, false, None, false),
            ("cordoned", Some("True"), true, None, false),
            ("NoSchedule", Some("True"), false, Some("NoSchedule"), false),
            ("NoExecute", Some("True"), false, Some("NoExecute"), false),
            ("deleting", Some("True"), false, None, true),
        ] {
            let mut target = placement_node("worker-b");
            target.status.as_mut().unwrap().conditions = ready.map(|ready| {
                serde_json::from_value(serde_json::json!([
                    { "type": "Ready", "status": ready }
                ]))
                .unwrap()
            });
            target.spec = Some(
                serde_json::from_value(serde_json::json!({
                    "unschedulable": cordoned,
                    "taints": taint.map(|effect| serde_json::json!([
                        { "key": "dedicated", "value": "other", "effect": effect }
                    ]))
                }))
                .unwrap(),
            );
            if deleting {
                target.metadata.deletion_timestamp = Some(
                    serde_json::from_value(serde_json::json!("2026-01-01T00:00:00Z")).unwrap(),
                );
            }
            let mut inventory = vec![placement_node("worker-a")];
            if case != "missing" {
                inventory.push(target);
            }
            assert_eq!(
                select_node(
                    inventory.clone(),
                    &[],
                    &admitted,
                    &labels,
                    KubeResources::default(),
                    None,
                )
                .unwrap(),
                "worker-a",
                "{case}",
            );
            assert!(
                select_node(
                    inventory,
                    &[],
                    &admitted,
                    &labels,
                    KubeResources::default(),
                    Some("worker-b"),
                )
                .is_err(),
                "{case}",
            );
        }
    }

    #[test]
    fn explicit_target_checks_capacity_and_reservations_without_fallback() {
        let admitted =
            std::collections::BTreeSet::from(["worker-a".to_owned(), "worker-b".to_owned()]);
        let labels = BTreeMap::from([("workload".to_owned(), "batch".to_owned())]);
        let request = KubeResources {
            cpu_millis: 1_000,
            memory_bytes: 1_073_741_824,
            gpu_count: 1,
            ..KubeResources::default()
        };
        for (resource, insufficient, exact, reserved) in [
            ("cpu", "999m", "1", Some("1m")),
            ("memory", "1073741823", "1Gi", Some("1")),
            ("nvidia.com/gpu", "0", "1", Some("1")),
            ("pods", "0", "1", None),
        ] {
            let mut target = placement_node("worker-b");
            target
                .status
                .as_mut()
                .unwrap()
                .allocatable
                .as_mut()
                .unwrap()
                .insert(resource.to_owned(), Quantity(insufficient.to_owned()));
            assert_eq!(
                select_node(
                    vec![placement_node("worker-a"), target.clone()],
                    &[],
                    &admitted,
                    &labels,
                    request,
                    None,
                )
                .unwrap(),
                "worker-a",
                "{resource}",
            );
            assert!(
                select_node(
                    vec![placement_node("worker-a"), target.clone()],
                    &[],
                    &admitted,
                    &labels,
                    request,
                    Some("worker-b"),
                )
                .is_err(),
                "insufficient {resource}",
            );
            target
                .status
                .as_mut()
                .unwrap()
                .allocatable
                .as_mut()
                .unwrap()
                .insert(resource.to_owned(), Quantity(exact.to_owned()));
            let inventory = vec![placement_node("worker-a"), target];
            assert_eq!(
                select_node(
                    inventory.clone(),
                    &[],
                    &admitted,
                    &labels,
                    request,
                    Some("worker-b"),
                )
                .unwrap(),
                "worker-b",
                "exact {resource} capacity",
            );
            let reservations: BTreeMap<_, _> = reserved
                .map(|quantity| (resource.to_owned(), quantity.to_owned()))
                .into_iter()
                .collect();
            let pod: Pod = serde_json::from_value(serde_json::json!({
                "metadata": { "name": "reserved" },
                "spec": {
                    "nodeName": "worker-b",
                    "containers": [{
                        "name": "worker",
                        "resources": { "requests": reservations }
                    }]
                },
                "status": { "phase": "Running" }
            }))
            .unwrap();
            assert_eq!(
                select_node(
                    inventory.clone(),
                    std::slice::from_ref(&pod),
                    &admitted,
                    &labels,
                    request,
                    None,
                )
                .unwrap(),
                "worker-a",
                "{resource} reservation",
            );
            assert!(
                select_node(
                    inventory,
                    &[pod],
                    &admitted,
                    &labels,
                    request,
                    Some("worker-b"),
                )
                .is_err(),
                "reserved {resource}",
            );
        }
    }

    #[test]
    fn unschedulable_wins_over_ready() {
        let node = |unschedulable: bool, ready: Option<&str>| -> Node {
            let mut status = serde_json::json!({
                "nodeInfo": {"architecture": "amd64"},
                "capacity": {"cpu": "4"},
            });
            if let Some(ready) = ready {
                status["conditions"] = serde_json::json!([{"type": "Ready", "status": ready}]);
            }
            serde_json::from_value(serde_json::json!({
                "spec": {"unschedulable": unschedulable},
                "status": status,
            }))
            .expect("node fixture")
        };
        let cordoned = node_facts(&node(true, Some("True"))).expect("cordoned node");
        assert_eq!(cordoned.state, KubeNodeState::Unschedulable);
        assert!(cordoned.unschedulable);
        assert_eq!(cordoned.architecture, "amd64");
        assert_eq!(cordoned.capacity.cpu_millis, 4000);
        let not_ready = node_facts(&node(false, Some("False"))).expect("not ready");
        assert_eq!(not_ready.state, KubeNodeState::NotReady);
        assert!(!not_ready.unschedulable);
        let unknown = node_facts(&node(false, None)).expect("no ready condition");
        assert_eq!(unknown.state, KubeNodeState::Unknown);
    }
}
