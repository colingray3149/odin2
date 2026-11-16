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

/// The refusal prefix when every admitted node is short of room right now; the launch
/// queue waits on it, while other refusals settle.
pub const CAPACITY_REFUSAL: &str = "no admitted node has room for the pod's requests";
const HOSTNAME_LABEL: &str = "kubernetes.io/hostname";

/// What a node must carry beyond room: exact labels, and integer labels at or above a floor.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeRequirements {
    pub labels: BTreeMap<String, String>,
    pub minimums: BTreeMap<String, u64>,
    /// Node taints (`odin.dev/<name>`) the launch tolerates. Without `external`, a node must
    /// carry the fleet trust label, which only the server sets.
    pub tolerate: std::collections::BTreeSet<String>,
}

impl NodeRequirements {
    pub fn labels(labels: BTreeMap<String, String>) -> Self {
        Self {
            labels,
            ..Self::default()
        }
    }

    /// Each requirement `node_labels` fails, as `key=value` or `key>=floor`.
    pub fn missing(&self, node_labels: &BTreeMap<String, String>) -> Vec<String> {
        let trust = (!self
            .tolerate
            .contains(odin_registry::schema::EXTERNAL_TOLERATION))
        .then(|| {
            (
                odin_registry::schema::NODE_TRUST_LABEL.to_owned(),
                odin_registry::schema::NODE_TRUST_FLEET.to_owned(),
            )
        });
        let exact = self
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .chain(trust)
            .filter(|(key, value)| node_labels.get(key) != Some(value))
            .map(|(key, value)| format!("{key}={value}"));
        let floors = self
            .minimums
            .iter()
            .filter(|(key, floor)| {
                node_labels
                    .get(*key)
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_none_or(|value| value < **floor)
            })
            .map(|(key, floor)| format!("{key}>={floor}"));
        exact.chain(floors).collect()
    }
}

pub fn is_capacity_refusal(error: &KubeError) -> bool {
    matches!(error, KubeError::Unavailable { reason } if reason.starts_with(CAPACITY_REFUSAL))
}

/// Returns a node name for required node affinity. The caller must retain scheduler
/// admission, rather than bypassing resource checks through `PodSpec.node_name`.
pub async fn choose_node(
    client: &KubeClient,
    required: &NodeRequirements,
    request: KubeResources,
    target: Option<&str>,
    data: &[crate::workload::WorkloadDataMount],
) -> Result<String, KubeError> {
    let allowed = data_admitting(&client.config, data);
    if allowed.is_empty() && !data.is_empty() {
        return Err(KubeError::rejected(format!(
            "no allowed node declares data roots covering {}",
            data_paths(data)
        )));
    }
    let (nodes, pods) = observe(client).await?;
    select_node(nodes, &pods, &allowed, required, request, target)
}

/// The allowed nodes whose declared data roots cover every data mount's host path.
pub(crate) fn data_admitting(
    config: &crate::KubeConfig,
    data: &[crate::workload::WorkloadDataMount],
) -> std::collections::BTreeSet<String> {
    config
        .allowed_nodes
        .iter()
        .filter(|node| node_covers(config, node, data))
        .cloned()
        .collect()
}

pub(crate) fn node_covers(
    config: &crate::KubeConfig,
    node: &str,
    data: &[crate::workload::WorkloadDataMount],
) -> bool {
    data.iter().all(|mount| {
        config.node_data_roots.get(node).is_some_and(|roots| {
            roots
                .iter()
                .any(|root| std::path::Path::new(&mount.host_path).starts_with(root))
        })
    })
}

pub(crate) fn data_paths(data: &[crate::workload::WorkloadDataMount]) -> String {
    data.iter()
        .map(|mount| mount.host_path.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Refuses before a pod is created unless one of `nodes` has room for `request`; the
/// scheduler would otherwise leave it Pending. Returns the node it fits on.
pub async fn require_room(
    client: &KubeClient,
    nodes: &std::collections::BTreeSet<String>,
    request: KubeResources,
) -> Result<String, KubeError> {
    let (candidates, pods) = observe(client).await?;
    select_node(
        candidates,
        &pods,
        nodes,
        &NodeRequirements::default(),
        request,
        None,
    )
}

async fn observe(client: &KubeClient) -> Result<(Vec<Node>, Vec<Pod>), KubeError> {
    let node_api: kube::Api<Node> = kube::Api::all(client.client.clone());
    let pod_api: kube::Api<Pod> = kube::Api::all(client.client.clone());
    let nodes = tokio::time::timeout(
        client.config.request_timeout,
        node_api.list(&ListParams::default().limit(1024)),
    )
    .await
    .map_err(|error| {
        KubeError::unavailable(format!("node placement observation timed out: {error}"))
    })??;
    let pods = tokio::time::timeout(
        client.config.request_timeout,
        pod_api.list(&ListParams::default().limit(4096)),
    )
    .await
    .map_err(|error| {
        KubeError::unavailable(format!("pod reservation observation timed out: {error}"))
    })??;
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
    Ok((nodes.items, pods.items))
}

/// The node a pod with no `nodeName` yet is pinned to: a hostname `nodeSelector`, or a
/// single required affinity value. The scheduler still has to place it, so its requests
/// count against that node until it runs.
pub(crate) fn pinned_node(spec: &PodSpec) -> Option<&str> {
    if let Some(node) = &spec.node_name {
        return Some(node);
    }
    if let Some(node) = spec
        .node_selector
        .as_ref()
        .and_then(|selector| selector.get(HOSTNAME_LABEL))
    {
        return Some(node);
    }
    let terms = &spec
        .affinity
        .as_ref()?
        .node_affinity
        .as_ref()?
        .required_during_scheduling_ignored_during_execution
        .as_ref()?
        .node_selector_terms;
    // Alternative terms pin nothing; a single term pins when one of its requirements names one node.
    let [term] = terms.as_slice() else {
        return None;
    };
    term.match_expressions
        .iter()
        .flatten()
        .chain(term.match_fields.iter().flatten())
        .find_map(|requirement| {
            let pins = matches!(requirement.key.as_str(), HOSTNAME_LABEL | "metadata.name")
                && requirement.operator == "In";
            match requirement.values.as_deref() {
                Some([node]) if pins => Some(node.as_str()),
                _ => None,
            }
        })
}

/// Requests each node has committed to: its placed pods and pods pinned to it.
fn reservations(pods: &[Pod]) -> Result<BTreeMap<String, (KubeResources, u64)>, KubeError> {
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
            if let Some(node) = pinned_node(spec) {
                let reservation = reservations.entry(node.to_owned()).or_default();
                add(&mut reservation.0, &pod_reservation(pod, spec)?)?;
                reservation.1 = reservation.1.checked_add(1).ok_or_else(arithmetic_error)?;
            }
        }
    }
    Ok(reservations)
}

pub(crate) fn select_node(
    mut candidates: Vec<Node>,
    pods: &[Pod],
    allowed_nodes: &std::collections::BTreeSet<String>,
    required: &NodeRequirements,
    request: KubeResources,
    target: Option<&str>,
) -> Result<String, KubeError> {
    require_placement_authority(allowed_nodes, target)?;
    let reservations = reservations(pods)?;
    candidates.sort_unstable_by(|left, right| left.metadata.name.cmp(&right.metadata.name));
    let mut refused = Vec::new();
    // A node that could not hold the request even when empty will never take it.
    let mut could_ever_hold = false;
    for node in candidates {
        let Some(name) = node.metadata.name.as_deref() else {
            continue;
        };
        if !allowed_nodes.contains(name)
            || target.is_some_and(|target| target != name)
            || !schedulable(&node, &required.tolerate)
        {
            continue;
        }
        let no_labels = BTreeMap::new();
        if !required
            .missing(node.metadata.labels.as_ref().unwrap_or(&no_labels))
            .is_empty()
        {
            continue;
        }
        let used = reservations.get(name).copied().unwrap_or_default();
        let short = shortfall(&node, used, request)?;
        if short.is_empty() {
            return Ok(name.to_owned());
        }
        could_ever_hold |= shortfall(&node, Default::default(), request)?.is_empty();
        refused.push(format!("{name} lacks {}", short.join(", ")));
    }
    if refused.is_empty() {
        return Err(KubeError::unavailable(
            "no ready schedulable node satisfies the Job capabilities and resource reservations",
        ));
    }
    if !could_ever_hold {
        return Err(KubeError::rejected(format!(
            "no admitted node is large enough for the pod's requests: {}",
            refused.join("; ")
        )));
    }
    Err(KubeError::unavailable(format!(
        "{CAPACITY_REFUSAL}: {}",
        refused.join("; ")
    )))
}

/// What `node` lacks for `request` beyond `used` (its reservations and pod count); empty
/// when it has room.
fn shortfall(
    node: &Node,
    (used, pods): (KubeResources, u64),
    request: KubeResources,
) -> Result<Vec<&'static str>, KubeError> {
    let status = node.status.as_ref();
    let allocatable = resource_requirements(status.and_then(|status| status.allocatable.as_ref()))?;
    let slots = status
        .and_then(|status| status.allocatable.as_ref())
        .and_then(|values| values.get("pods"))
        .map_or(Ok(0), |value| quantity_units(&value.0, 1))?;
    let lacks = [
        (
            request.cpu_millis > allocatable.cpu_millis.saturating_sub(used.cpu_millis),
            "cpu",
        ),
        (
            request.memory_bytes > allocatable.memory_bytes.saturating_sub(used.memory_bytes),
            "memory",
        ),
        (
            request.ephemeral_storage_bytes
                > allocatable
                    .ephemeral_storage_bytes
                    .saturating_sub(used.ephemeral_storage_bytes),
            "ephemeral storage",
        ),
        (
            request.gpu_count > allocatable.gpu_count.saturating_sub(used.gpu_count),
            "GPU",
        ),
        (pods >= slots, "pod slots"),
    ];
    Ok(lacks
        .into_iter()
        .filter_map(|(short, name)| short.then_some(name))
        .collect())
}

/// The read-only view of one node object; `revision` is the caller's
/// ordinal (the catalog stamps the durable one).
pub fn node_view(cluster: &str, node: &Node, revision: u64) -> Result<KubeNodeView, KubeError> {
    let name = node.metadata.name.as_ref().ok_or_else(arithmetic_error)?;
    let uid = node.metadata.uid.as_ref().ok_or_else(arithmetic_error)?;
    let facts = node_facts(node)?;
    Ok(KubeNodeView {
        node_id: NodeId::new(name).map_err(|error| {
            KubeError::rejected(format!("node name has no valid Odin identity: {error}"))
        })?,
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
        mode: facts.mode,
    })
}

pub(crate) struct NodeFacts {
    pub state: KubeNodeState,
    pub unschedulable: bool,
    pub architecture: String,
    pub operating_system: String,
    pub capacity: KubeResources,
    pub allocatable: KubeResources,
    pub mode: Option<String>,
}

/// `Unschedulable` spec wins, then the `Ready` condition, else `Unknown`.
/// A node's allocatable CPU in millicores, the denominator of a pod's share of its price.
pub fn allocatable_cpu_millis(node: &Node) -> Result<u64, KubeError> {
    node_facts(node).map(|facts| facts.allocatable.cpu_millis)
}

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
        mode: node
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(crate::node_admin::NODE_MODE_ANNOTATION))
            .cloned(),
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

/// Ready, not cordoned, and every blocking taint is one the launch tolerates.
fn schedulable(node: &Node, tolerate: &std::collections::BTreeSet<String>) -> bool {
    let tolerated = |key: &str| {
        key.strip_prefix(odin_registry::schema::NODE_TAINT_PREFIX)
            .is_some_and(|name| tolerate.contains(name))
    };
    if node.metadata.deletion_timestamp.is_some()
        || node.spec.as_ref().is_some_and(|spec| {
            spec.unschedulable == Some(true)
                || spec.taints.as_ref().is_some_and(|taints| {
                    taints.iter().any(|taint| {
                        matches!(taint.effect.as_str(), "NoSchedule" | "NoExecute")
                            && !tolerated(&taint.key)
                    })
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
        gpu_count: u32::try_from(value("nvidia.com/gpu", 1)?)
            .map_err(|error| KubeError::rejected(format!("GPU count does not fit u32: {error}")))?,
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

pub fn pod_requests(spec: &PodSpec) -> Result<KubeResources, KubeError> {
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
        let exponent: i32 = numeric[index + 1..].parse().map_err(|error| {
            KubeError::rejected(format!("quantity {raw:?} has an invalid exponent: {error}"))
        })?;
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
    u64::try_from(result)
        .map_err(|error| KubeError::rejected(format!("quantity {raw:?} exceeds u64: {error}")))
}

fn arithmetic_error() -> KubeError {
    KubeError::Rejected {
        reason: "Kubernetes resource quantity is invalid or exceeds bounded accounting".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placement_node(name: &str) -> Node {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": name,
                "labels": { "workload": "batch", "node-restriction.kubernetes.io/odin-trust": "fleet" }
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

    fn external_node(name: &str) -> Node {
        let mut node = placement_node(name);
        node.metadata
            .labels
            .as_mut()
            .unwrap()
            .remove("node-restriction.kubernetes.io/odin-trust");
        node.spec = Some(
            serde_json::from_value(serde_json::json!({
                "taints": [{ "key": "odin.dev/external", "value": "true", "effect": "NoSchedule" }]
            }))
            .unwrap(),
        );
        node
    }

    #[test]
    fn a_tainted_node_takes_only_tolerating_launches() {
        let admitted = ["rented".to_owned()].into_iter().collect();
        let request = KubeResources::default();
        let fleet_only = NodeRequirements::default();
        assert!(select_node(
            vec![external_node("rented")],
            &[],
            &admitted,
            &fleet_only,
            request,
            None
        )
        .is_err());
        let tolerating = NodeRequirements {
            tolerate: ["external".to_owned()].into_iter().collect(),
            ..NodeRequirements::default()
        };
        assert_eq!(
            select_node(
                vec![external_node("rented")],
                &[],
                &admitted,
                &tolerating,
                request,
                None
            )
            .unwrap(),
            "rented"
        );
        // Tolerating one taint does not tolerate another.
        let mut other = external_node("rented");
        other.spec.as_mut().unwrap().taints.as_mut().unwrap()[0].key =
            "odin.dev/maintenance".to_owned();
        assert!(select_node(vec![other], &[], &admitted, &tolerating, request, None).is_err());
    }

    #[test]
    fn an_untrusted_node_never_takes_a_fleet_launch() {
        // A hostile kubelet may label itself with any capability, but not the trust label.
        let mut untrusted = external_node("rented");
        untrusted.spec = None;
        untrusted
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert("odin.capability/simulation".to_owned(), "true".to_owned());
        let admitted = ["rented".to_owned(), "mini".to_owned()]
            .into_iter()
            .collect();
        let required = NodeRequirements::labels(BTreeMap::from([(
            "odin.capability/simulation".to_owned(),
            "true".to_owned(),
        )]));
        assert!(select_node(
            vec![untrusted.clone()],
            &[],
            &admitted,
            &required,
            KubeResources::default(),
            None
        )
        .is_err());
        let mut mini = placement_node("mini");
        mini.metadata
            .labels
            .as_mut()
            .unwrap()
            .insert("odin.capability/simulation".to_owned(), "true".to_owned());
        assert_eq!(
            select_node(
                vec![untrusted, mini],
                &[],
                &admitted,
                &required,
                KubeResources::default(),
                None
            )
            .unwrap(),
            "mini"
        );
    }

    #[test]
    fn min_vram_selects_only_nodes_labelled_at_or_above() {
        let labelled = |name: &str, vram: Option<&str>| {
            let mut node = placement_node(name);
            if let Some(vram) = vram {
                node.metadata
                    .labels
                    .get_or_insert_with(BTreeMap::new)
                    .insert("odin.gpu/vram-gib".to_owned(), vram.to_owned());
            }
            node
        };
        let admitted = ["small", "large", "plain", "odd"]
            .map(str::to_owned)
            .into_iter()
            .collect();
        let required = NodeRequirements {
            minimums: BTreeMap::from([("odin.gpu/vram-gib".to_owned(), 12)]),
            ..NodeRequirements::default()
        };
        let inventory = || {
            vec![
                labelled("small", Some("8")),
                labelled("plain", None),
                labelled("odd", Some("lots")),
                labelled("large", Some("32")),
            ]
        };
        let request = KubeResources::default();
        assert_eq!(
            select_node(inventory(), &[], &admitted, &required, request, None).unwrap(),
            "large"
        );
        for refused in ["small", "plain", "odd"] {
            assert!(
                select_node(
                    inventory(),
                    &[],
                    &admitted,
                    &required,
                    request,
                    Some(refused)
                )
                .is_err(),
                "{refused} is below the floor or unlabelled"
            );
        }
        let exact = NodeRequirements {
            minimums: BTreeMap::from([("odin.gpu/vram-gib".to_owned(), 8)]),
            ..NodeRequirements::default()
        };
        assert!(select_node(inventory(), &[], &admitted, &exact, request, Some("small")).is_ok());
        assert!(required
            .missing(&BTreeMap::new())
            .contains(&"odin.gpu/vram-gib>=12".to_owned()));
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
                select_node(
                    inventory,
                    &[],
                    &admitted,
                    &NodeRequirements::labels(labels.clone()),
                    request,
                    None
                )
                .unwrap(),
                "worker-b",
            );
        }
        assert!(select_node(
            vec![node("worker-a"), node("worker-b")],
            &[],
            &admitted,
            &NodeRequirements::labels(labels.clone()),
            request,
            Some("worker-a"),
        )
        .is_err());
        assert!(select_node(
            vec![node("worker-a")],
            &[],
            &Default::default(),
            &NodeRequirements::labels(labels.clone()),
            request,
            None,
        )
        .is_err());
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
                    &NodeRequirements::labels(labels.clone()),
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
                    &NodeRequirements::labels(labels.clone()),
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
                    &NodeRequirements::labels(labels.clone()),
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
                    &NodeRequirements::labels(labels.clone()),
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
                    &NodeRequirements::labels(labels.clone()),
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
                    &NodeRequirements::labels(labels.clone()),
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
                    &NodeRequirements::labels(labels.clone()),
                    request,
                    Some("worker-b"),
                )
                .is_err(),
                "reserved {resource}",
            );
        }
    }

    #[test]
    fn a_pending_pod_pinned_to_a_node_holds_its_requests_before_it_runs() {
        const GIB: u64 = 1 << 30;
        let admitted =
            std::collections::BTreeSet::from(["worker-a".to_owned(), "worker-b".to_owned()]);
        let labels = BTreeMap::new();
        let request = KubeResources {
            memory_bytes: 2 * GIB,
            ..KubeResources::default()
        };
        let inventory = || vec![placement_node("worker-a"), placement_node("worker-b")];
        // Pending with no nodeName: only its affinity says where it will run.
        let pinned = |node: &str| -> Pod {
            serde_json::from_value(serde_json::json!({
                "metadata": { "name": format!("pending-{node}") },
                "spec": {
                    "containers": [{
                        "name": "worker",
                        "resources": { "requests": { "memory": "7Gi" } }
                    }],
                    "affinity": { "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [{ "matchExpressions": [{
                                "key": "kubernetes.io/hostname",
                                "operator": "In",
                                "values": [node]
                            }] }]
                        }
                    } }
                },
                "status": { "phase": "Pending" }
            }))
            .unwrap()
        };
        assert_eq!(
            select_node(
                inventory(),
                &[],
                &admitted,
                &NodeRequirements::labels(labels.clone()),
                request,
                None
            )
            .unwrap(),
            "worker-a",
        );
        assert_eq!(
            select_node(
                inventory(),
                &[pinned("worker-a")],
                &admitted,
                &NodeRequirements::labels(labels.clone()),
                request,
                None,
            )
            .unwrap(),
            "worker-b",
        );
        let refused = select_node(
            inventory(),
            &[pinned("worker-a"), pinned("worker-b")],
            &admitted,
            &NodeRequirements::labels(labels.clone()),
            request,
            None,
        )
        .unwrap_err();
        assert!(is_capacity_refusal(&refused), "{refused}");
        assert!(
            refused.to_string().contains("worker-a lacks memory"),
            "{refused}"
        );
    }

    #[test]
    fn a_pod_no_admitted_node_can_hold_is_rejected_not_queued() {
        let admitted = std::collections::BTreeSet::from(["worker-a".to_owned()]);
        let request = KubeResources {
            memory_bytes: 16 * 1024 * 1024 * 1024,
            ..KubeResources::default()
        };
        let error = select_node(
            vec![placement_node("worker-a")],
            &[],
            &admitted,
            &NodeRequirements::default(),
            request,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, KubeError::Rejected { .. }), "{error}");
        assert!(!is_capacity_refusal(&error));
    }
}
