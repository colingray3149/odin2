//! Projects registry declarations, reachability probes, zellij observations, and k3s state.
//! Last-seen timestamps advance only for online hosts and remain available when hosts go offline.
//! TCP probes send no payload and use a fixed timeout; missing endpoints report Unknown.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::read_model::{ProjectionMetadata, ReadModelCapture};
use async_trait::async_trait;
use futures_util::future::join_all;
use odin_domain::huginn::{
    FleetHostView, FleetPlacementView, FleetTailnetState, Freshness, FreshnessState, KubeNodeState,
    KubeNodeView, KubeWorkloadView, ObjectKind, ObjectRef, ObjectSnapshot, QueryScope, Revision,
    RevisionSource,
};
use odin_domain::Digest;
use odin_registry::schema::{HostToml, NodeToml};
use odin_registry::{ObjectConfig, RegistryKind, Snapshot};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::net::TcpStream;

/// The wall-clock ceiling of one reachability probe. A probe either answers
/// within this budget or resolves `Unreachable`; it never hangs the pass.
pub const FLEET_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the daemon re-observes the fleet between registry revisions.
pub const FLEET_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// The bound on workload names carried by one `pods` placement.
pub const FLEET_POD_NAMES_LIMIT: usize = 20;

/// One bounded reachability observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reachability {
    /// The probe connected within the budget.
    Reachable,
    /// The probe failed, was refused, or timed out within the budget.
    Unreachable,
    /// Nothing was declared to probe: declared absence, never a failure.
    Unknown,
}

impl From<Reachability> for FleetTailnetState {
    fn from(reachability: Reachability) -> Self {
        match reachability {
            Reachability::Reachable => Self::Reachable,
            Reachability::Unreachable => Self::Unreachable,
            Reachability::Unknown => Self::Unknown,
        }
    }
}

/// The fleet liveness probe port. Implementations must be bounded: one
/// observation per call resolves within a fixed budget, never an unbounded
/// cross-host wait.
#[async_trait]
pub trait FleetProbe: Send + Sync {
    /// Observes one declared host: its tailscale name and, when a hosted
    /// node declares one, the gateway endpoint to probe. CONNECT only —
    /// an implementation never sends payload bytes to the probed service.
    async fn reachable(&self, host_tailnet: &str, endpoint: Option<&str>) -> Reachability;
}

/// The production probe: one connect-only TCP dial to the declared
/// endpoint's host and effective port under [`FLEET_PROBE_TIMEOUT`]. A
/// malformed or undeclared endpoint and every connect/timeout failure
/// resolve to a typed [`Reachability`], never a panic and never a hang.
pub struct TcpFleetProbe;

/// Unlike pod egress, daemon probes allow loopback targets for co-located gateways.
fn probe_target(endpoint: &str) -> Option<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return None;
    }
    let url = url::Url::parse(endpoint).ok()?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = match url.host()? {
        url::Host::Domain(domain) => domain.to_owned(),
        url::Host::Ipv4(address) => address.to_string(),
        url::Host::Ipv6(address) => address.to_string(),
    };
    let port = url.port_or_known_default().filter(|port| *port != 0)?;
    Some(format!("{host}:{port}"))
}

#[async_trait]
impl FleetProbe for TcpFleetProbe {
    async fn reachable(&self, _host_tailnet: &str, endpoint: Option<&str>) -> Reachability {
        let Some(endpoint) = endpoint else {
            return Reachability::Unknown;
        };
        // A declared endpoint with no extractable connect target is a
        // broken declaration, not an absence: fail closed to Unreachable.
        let Some(target) = probe_target(endpoint) else {
            return Reachability::Unreachable;
        };
        match tokio::time::timeout(FLEET_PROBE_TIMEOUT, TcpStream::connect(target)).await {
            Ok(Ok(_socket)) => Reachability::Reachable,
            Ok(Err(_refused)) => Reachability::Unreachable,
            Err(_elapsed) => Reachability::Unreachable,
        }
    }
}

/// Probes every declared host concurrently. Each probe is individually
/// bounded by the implementation (the TCP probe carries
/// [`FLEET_PROBE_TIMEOUT`]), so the whole fan-out resolves within one probe
/// budget — never a serial wait and never a hang.
pub async fn probe_hosts<P, I>(probe: &P, hosts: I) -> BTreeMap<String, Reachability>
where
    P: FleetProbe + ?Sized,
    I: IntoIterator<Item = (String, String, Option<String>)>,
{
    let probes: Vec<_> = hosts
        .into_iter()
        .map(|(host, tailscale, endpoint)| async move {
            let reachability = probe.reachable(&tailscale, endpoint.as_deref()).await;
            (host, reachability)
        })
        .collect();
    join_all(probes).await.into_iter().collect()
}

/// The bound on session names carried by one `zellij-sessions` placement.
pub const FLEET_ZELLIJ_NAMES_LIMIT: usize = 20;

/// One bounded zellij session observation for one host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZellijSessions {
    /// The host answered within the bound: its zellij session names.
    Live(Vec<String>),
    /// The probe failed, timed out, or answered nothing usable. Typed
    /// unreachability — never a fabricated live reading.
    Unreachable,
}

/// The fleet zellij-session probe port. Implementations must be bounded:
/// one observation per call resolves within a fixed budget, never an
/// unbounded cross-host wait.
#[async_trait]
pub trait FleetZellijProbe: Send + Sync {
    /// Observes one declared host by its tailscale name. Read-only: an
    /// implementation lists sessions and never attaches to, creates, or
    /// kills one.
    async fn sessions(&self, host_tailnet: &str) -> ZellijSessions;
}

/// Probes the zellij sessions of every declared host concurrently. Each
/// probe is individually bounded by the implementation, so the whole
/// fan-out resolves within one probe budget — never a serial wait and
/// never a hang.
pub async fn probe_zellij_sessions<P, I>(probe: &P, hosts: I) -> BTreeMap<String, ZellijSessions>
where
    P: FleetZellijProbe + ?Sized,
    I: IntoIterator<Item = (String, String)>,
{
    let probes: Vec<_> = hosts
        .into_iter()
        .map(|(host, tailscale)| async move {
            let sessions = probe.sessions(&tailscale).await;
            (host, sessions)
        })
        .collect();
    join_all(probes).await.into_iter().collect()
}

/// The k3s facts the fleet producer consumes, extracted from a shared
/// read-model capture: node Ready state per node name and workload names
/// per node. Objects that are not typed kube node/workload views (for
/// example registry-seeded node declarations riding the same kind) are
/// skipped, so hosts without cluster observations keep `k3sNodeState: null`
/// instead of a fabricated state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FleetKubeState {
    /// Node Ready state keyed by the k3s node name (the registry node id).
    pub node_states: BTreeMap<String, KubeNodeState>,
    /// Workload names keyed by the node they are scheduled on, sorted.
    pub workloads: BTreeMap<String, Vec<String>>,
}

impl FleetKubeState {
    pub fn absent() -> Self {
        Self::default()
    }

    /// Extracts the typed kube facts from one read-model capture. Names are
    /// sorted so the projection is a pure function of the captured state.
    pub fn from_capture(capture: &ReadModelCapture) -> Self {
        let mut state = Self::absent();
        for object in &capture.objects {
            match object.object.kind {
                ObjectKind::Node => {
                    let Ok(view) = serde_json::from_value::<KubeNodeView>(object.value.clone())
                    else {
                        continue;
                    };
                    state
                        .node_states
                        .insert(view.node_id.as_str().to_owned(), view.state);
                }
                ObjectKind::KubeResource => {
                    let Ok(view) = serde_json::from_value::<KubeWorkloadView>(object.value.clone())
                    else {
                        continue;
                    };
                    let Some(node) = view.node_id else {
                        continue;
                    };
                    state
                        .workloads
                        .entry(node.as_str().to_owned())
                        .or_default()
                        .push(view.resource.name);
                }
                _ => {}
            }
        }
        for names in state.workloads.values_mut() {
            names.sort();
        }
        state
    }
}

/// Live session counts folded into the `seat-sessions` placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FleetSessionCounts {
    /// Excludes Ended and Failed sessions, which no longer consume capacity.
    pub active_sessions: u32,
}

impl FleetSessionCounts {
    /// Extracts the count from one read-model capture, or `None` when the
    /// capture carried no Session objects at all — the placement is then
    /// omitted rather than fabricated as zero.
    pub fn from_capture(capture: &ReadModelCapture) -> Option<Self> {
        let mut seen = false;
        let mut active = 0u32;
        for object in &capture.objects {
            if object.object.kind != ObjectKind::Session {
                continue;
            }
            seen = true;
            let state = object
                .value
                .get("state")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if !matches!(state, "ended" | "failed") {
                active += 1;
            }
        }
        seen.then_some(Self {
            active_sessions: active,
        })
    }
}

/// One projected fleet object with the projection metadata its upsert
/// carries — the producer-recipe pairing of [`ObjectSnapshot`] and
/// [`ProjectionMetadata`].
#[derive(Clone, Debug)]
pub struct FleetProjection {
    pub snapshot: ObjectSnapshot,
    pub metadata: ProjectionMetadata,
}

/// One declared enabled node with its registry id (the k3s node name key).
struct NodeEntry<'a> {
    id: &'a str,
    node: &'a NodeToml,
}

/// One enabled+enrolled declared host with the enabled nodes naming it.
struct HostEntry<'a> {
    host: &'a HostToml,
    nodes: Vec<NodeEntry<'a>>,
}

/// Projects the fleet read model: one [`FleetHostView`] object per
/// enabled+enrolled declared host and one [`FleetPlacementView`] object per
/// placed thing (the odind authority, per-node gateways, per-node pods, the
/// authority host's live sessions, and each host's live zellij sessions).
///
/// `probes` maps host id to the bounded probe outcome for this pass.
/// `zellij` maps host id to the bounded zellij session observation for
/// this pass; a host it does not cover projects no zellij placement rather
/// than a fabricated one.
/// `last_seen` is the caller-owned cross-pass memory: entries advance only
/// when a host proves alive, and the projected `lastSeen` always reads the
/// post-pass map. `current` holds the fleet objects already materialized in
/// the read model (by object id), so unchanged views keep their exact
/// snapshot — an unchanged pass yields no objects, moves no revision, and
/// wakes no downstream rebuild — and changed views bump their revision by
/// exactly one.
#[allow(clippy::too_many_arguments)]
pub fn project_fleet(
    registry: &Snapshot,
    probes: &BTreeMap<String, Reachability>,
    zellij: &BTreeMap<String, ZellijSessions>,
    kube: &FleetKubeState,
    sessions: Option<&FleetSessionCounts>,
    last_seen: &mut BTreeMap<String, OffsetDateTime>,
    current: &BTreeMap<String, ObjectSnapshot>,
    observed_at: OffsetDateTime,
) -> Vec<FleetProjection> {
    let mut hosts: BTreeMap<&str, HostEntry<'_>> = BTreeMap::new();
    for object in registry.listed_objects(RegistryKind::Host) {
        let ObjectConfig::Host(host) = &object.config else {
            continue;
        };
        // The listing already filters to enabled objects; enrolled is the
        // host-liveness gate the listing does not express.
        if !host.enrolled {
            continue;
        }
        hosts.insert(
            object.id.as_str(),
            HostEntry {
                host,
                nodes: Vec::new(),
            },
        );
    }
    for object in registry.listed_objects(RegistryKind::Node) {
        let ObjectConfig::Node(node) = &object.config else {
            continue;
        };
        if let Some(entry) = hosts.get_mut(node.host.as_str()) {
            entry.nodes.push(NodeEntry {
                id: object.id.as_str(),
                node,
            });
        }
    }

    let mut projections = Vec::new();
    for (&host_id, entry) in &hosts {
        let view = project_host(
            host_id,
            entry,
            probes
                .get(host_id)
                .copied()
                .unwrap_or(Reachability::Unknown),
            zellij.get(host_id),
            kube,
            last_seen,
            observed_at,
        );
        let title = format!("Fleet host {host_id}");
        let summary = host_liveness_summary(&view);
        if let Some(projection) = fleet_projection(
            ObjectKind::FleetHost,
            host_id.to_owned(),
            &view,
            &title,
            &summary,
            current,
            observed_at,
        ) {
            projections.push(projection);
        }
    }

    // Snapshot ordering makes selection stable even if multiple nodes declare authority.
    let authority = hosts.iter().find_map(|(host_id, entry)| {
        entry
            .nodes
            .iter()
            .find(|node| node.node.authoritative_state)
            .map(|node| (*host_id, node.id))
    });
    if let Some((host_id, node_id)) = authority {
        if let Some(projection) = fleet_projection(
            ObjectKind::FleetPlacement,
            "fleet:placement:authority".to_owned(),
            &FleetPlacementView {
                thing: "odind-authority".to_owned(),
                node: Some(node_id.to_owned()),
                host: Some(host_id.to_owned()),
                endpoint: None,
                count: None,
                names: Vec::new(),
                active_count: None,
                live: None,
            },
            "Placement odind-authority",
            &format!("Placement odind-authority: node {node_id} host {host_id}"),
            current,
            observed_at,
        ) {
            projections.push(projection);
        }
        if let Some(counts) = sessions {
            if let Some(projection) = fleet_projection(
                ObjectKind::FleetPlacement,
                "fleet:placement:seat-sessions".to_owned(),
                &FleetPlacementView {
                    thing: "seat-sessions".to_owned(),
                    node: None,
                    host: Some(host_id.to_owned()),
                    endpoint: None,
                    count: None,
                    names: Vec::new(),
                    active_count: Some(counts.active_sessions),
                    live: None,
                },
                "Placement seat-sessions",
                &format!(
                    "Placement seat-sessions: host {host_id}; active sessions {}",
                    counts.active_sessions
                ),
                current,
                observed_at,
            ) {
                projections.push(projection);
            }
        }
    }

    for (host_id, node) in hosts
        .iter()
        .flat_map(|(host_id, entry)| entry.nodes.iter().map(move |node| (*host_id, node)))
    {
        if let Some(endpoint) = &node.node.gateway_endpoint {
            if let Some(projection) = fleet_projection(
                ObjectKind::FleetPlacement,
                format!("fleet:placement:gateway:{}", node.id),
                &FleetPlacementView {
                    thing: "gateway".to_owned(),
                    node: Some(node.id.to_owned()),
                    host: Some(host_id.to_owned()),
                    endpoint: Some(endpoint.clone()),
                    count: None,
                    names: Vec::new(),
                    active_count: None,
                    live: None,
                },
                &format!("Placement gateway {}", node.id),
                &format!(
                    "Placement gateway: node {} host {host_id} endpoint {endpoint}",
                    node.id
                ),
                current,
                observed_at,
            ) {
                projections.push(projection);
            }
        }
        let Some(workloads) = kube.workloads.get(node.id) else {
            continue;
        };
        if workloads.is_empty() {
            continue;
        };
        let mut names: Vec<String> = workloads.clone();
        names.sort();
        names.truncate(FLEET_POD_NAMES_LIMIT);
        if let Some(projection) = fleet_projection(
            ObjectKind::FleetPlacement,
            format!("fleet:placement:pods:{}", node.id),
            &FleetPlacementView {
                thing: "pods".to_owned(),
                node: Some(node.id.to_owned()),
                host: Some(host_id.to_owned()),
                endpoint: None,
                count: Some(workloads.len() as u32),
                names,
                active_count: None,
                live: None,
            },
            &format!("Placement pods {}", node.id),
            &format!(
                "Placement pods: node {} host {host_id}: {} scheduled",
                node.id,
                workloads.len()
            ),
            current,
            observed_at,
        ) {
            projections.push(projection);
        }
    }

    // Per-host live zellij sessions: one placement per enabled+enrolled
    // host the zellij probe covered this pass. A host the probe did not
    // observe projects no placement rather than a fabricated one, and an
    // unreachable observation projects `live: false` with no names —
    // typed absence, never a live-looking empty list.
    for &host_id in hosts.keys() {
        let Some(observations) = zellij.get(host_id) else {
            continue;
        };
        let (live, mut names) = match observations {
            ZellijSessions::Live(names) => (true, names.clone()),
            ZellijSessions::Unreachable => (false, Vec::new()),
        };
        names.sort();
        names.dedup();
        names.truncate(FLEET_ZELLIJ_NAMES_LIMIT);
        let summary = match live {
            true => format!(
                "Placement zellij-sessions: host {host_id}: {} live sessions",
                names.len()
            ),
            false => format!("Placement zellij-sessions: host {host_id}: unreachable"),
        };
        if let Some(projection) = fleet_projection(
            ObjectKind::FleetPlacement,
            format!("fleet:placement:zellij:{host_id}"),
            &FleetPlacementView {
                thing: "zellij-sessions".to_owned(),
                node: None,
                host: Some(host_id.to_owned()),
                endpoint: None,
                count: None,
                names,
                active_count: None,
                live: Some(live),
            },
            &format!("Placement zellij-sessions {host_id}"),
            &summary,
            current,
            observed_at,
        ) {
            projections.push(projection);
        }
    }
    projections
}

/// Projects one declared host into its [`FleetHostView`] and advances the
/// caller's `last_seen` map when the host proves alive.
fn project_host(
    host_id: &str,
    entry: &HostEntry<'_>,
    reachability: Reachability,
    zellij: Option<&ZellijSessions>,
    kube: &FleetKubeState,
    last_seen: &mut BTreeMap<String, OffsetDateTime>,
    observed_at: OffsetDateTime,
) -> FleetHostView {
    let mut capabilities = BTreeSet::new();
    let mut allow_workloads = false;
    let mut authoritative_state = false;
    let mut gateway_endpoint: Option<String> = None;
    let mut k3s_node_state: Option<KubeNodeState> = None;
    let mut pods_scheduled = 0u32;
    for node in &entry.nodes {
        capabilities.extend(node.node.capabilities.iter().cloned());
        allow_workloads |= node.node.allow_workloads;
        authoritative_state |= node.node.authoritative_state;
        if gateway_endpoint.is_none() {
            gateway_endpoint.clone_from(&node.node.gateway_endpoint);
        }
        if k3s_node_state.is_none() {
            k3s_node_state = kube.node_states.get(node.id).copied();
        }
        pods_scheduled += kube.workloads.get(node.id).map(Vec::len).unwrap_or(0) as u32;
    }
    let tailnet = FleetTailnetState::from(reachability);
    // SSH activity also establishes liveness for hosts without a gateway or k3s node.
    let zellij_live = zellij.map(|sessions| matches!(sessions, ZellijSessions::Live(_)));
    let online = tailnet == FleetTailnetState::Reachable
        || k3s_node_state == Some(KubeNodeState::Ready)
        || zellij_live == Some(true);
    if online {
        last_seen.insert(host_id.to_owned(), observed_at);
    }
    FleetHostView {
        host: host_id.to_owned(),
        tailscale: entry.host.tailscale.clone(),
        hardware: entry.host.hardware.clone(),
        role: entry.host.role.clone(),
        capabilities: capabilities.into_iter().collect(),
        allow_workloads,
        authoritative_state,
        gateway_endpoint,
        tailnet,
        k3s_node_state,
        zellij_live,
        online,
        last_seen: last_seen.get(host_id).copied(),
        pods_scheduled,
    }
}

/// Builds one fleet snapshot only when the view actually changed: an
/// unchanged view returns `None` (no revision movement, no downstream
/// wake), a changed view bumps the materialized revision by exactly one.
fn fleet_projection<T: Serialize>(
    kind: ObjectKind,
    id: String,
    value: &T,
    title: &str,
    summary: &str,
    current: &BTreeMap<String, ObjectSnapshot>,
    observed_at: OffsetDateTime,
) -> Option<FleetProjection> {
    let value = serde_json::to_value(value).ok()?;
    let content_digest = Digest::hash(
        &serde_json::to_vec(&value).expect("serializing serde_json::Value cannot fail"),
    );
    let metadata =
        ProjectionMetadata::new(title.to_owned(), summary.to_owned()).in_scope(QueryScope::All);
    let revision = match current.get(&id) {
        None => Revision::new(1),
        Some(existing) if existing.content_digest == content_digest => return None,
        Some(existing) => existing.revision.checked_next()?,
    };
    Some(FleetProjection {
        snapshot: ObjectSnapshot {
            object: ObjectRef { kind, id },
            revision,
            revision_source: RevisionSource::Fleet,
            freshness: Freshness {
                state: FreshnessState::Fresh,
                observed_at,
                source_updated_at: Some(observed_at),
                stale_after_seconds: None,
            },
            content_digest,
            value,
        },
        metadata,
    })
}

pub fn host_liveness_summary(view: &FleetHostView) -> String {
    let mut summary = if view.online {
        let mut proofs = Vec::new();
        if view.k3s_node_state == Some(KubeNodeState::Ready) {
            proofs.push("k3s Ready".to_owned());
        }
        if view.tailnet == FleetTailnetState::Reachable {
            proofs.push("tailnet reachable".to_owned());
        }
        if view.zellij_live == Some(true) {
            proofs.push("ssh reachable".to_owned());
        }
        format!("online — {}", proofs.join(", "))
    } else {
        let tailnet = match view.tailnet {
            FleetTailnetState::Unreachable => "tailnet unreachable",
            FleetTailnetState::Unknown => "tailnet unknown",
            FleetTailnetState::Reachable => "tailnet reachable",
        };
        let k3s = match view.k3s_node_state {
            Some(state) => format!("k3s {state:?}"),
            None => "no k3s node".to_owned(),
        };
        format!("offline — {tailnet}, {k3s}")
    };
    summary.push_str("; last seen ");
    match view.last_seen {
        Some(seen) => summary.push_str(
            &seen
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        ),
        None => summary.push_str("never"),
    }
    summary
}

#[cfg(test)]
mod tests {
    use crate::read_model::MaterializedReadModel;
    use odin_domain::huginn::{
        FleetHostView, Freshness, FreshnessState, KubeNodeState, ObjectKind, ObjectRef,
        ObjectSnapshot, Revision,
    };
    use odin_registry::schema::REGISTRY_SCHEMA;
    use odin_registry::{ObjectConfig, RegistryKind, RegistryObject, Snapshot};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Instant;
    use time::OffsetDateTime;

    use super::{
        probe_zellij_sessions, project_fleet, FleetKubeState, FleetProbe, FleetSessionCounts,
        FleetZellijProbe, Reachability, TcpFleetProbe, ZellijSessions, FLEET_ZELLIJ_NAMES_LIMIT,
    };

    const OBSERVED: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    fn host_object(id: &str, tailscale: &str, enabled: bool, enrolled: bool) -> RegistryObject {
        RegistryObject {
            id: id.to_owned(),
            relative_config: PathBuf::from(format!("registry/hosts/{id}/host.toml")),
            config: ObjectConfig::Host(Box::new(odin_registry::schema::HostToml {
                schema: REGISTRY_SCHEMA.to_owned(),
                kind: RegistryKind::Host,
                enabled,
                description: format!("{id} declared host"),
                hardware: format!("{id}-hardware"),
                role: "worker".to_owned(),
                tailscale: tailscale.to_owned(),
                enrolled,
            })),
        }
    }

    fn node_object(
        id: &str,
        host: &str,
        authoritative: bool,
        gateway: Option<&str>,
        capabilities: &[&str],
    ) -> RegistryObject {
        RegistryObject {
            id: id.to_owned(),
            relative_config: PathBuf::from(format!("registry/nodes/{id}/node.toml")),
            config: ObjectConfig::Node(Box::new(odin_registry::schema::NodeToml {
                schema: REGISTRY_SCHEMA.to_owned(),
                kind: RegistryKind::Node,
                enabled: true,
                description: format!("{id} declared node"),
                host: host.to_owned(),
                role: "worker".to_owned(),
                capabilities: capabilities.iter().map(|name| name.to_string()).collect(),
                allow_workloads: true,
                authoritative_state: authoritative,
                gateway_endpoint: gateway.map(str::to_owned),
            })),
        }
    }

    fn fixture() -> Snapshot {
        Snapshot::build(
            1,
            vec![
                host_object("alpha", "alpha", true, true),
                host_object("beta", "beta", true, true),
                // Not enrolled: never projected, whatever its node declares.
                host_object("shadow", "shadow", true, false),
                host_object("spare", "spare", false, true),
                node_object(
                    "node-alpha",
                    "alpha",
                    false,
                    Some("http://alpha:14000/v1"),
                    &["build", "operator"],
                ),
                // The one authority: a host without a declared gateway and
                // without any k3s observation in this fixture.
                node_object("node-beta", "beta", true, None, &["operator"]),
                node_object(
                    "node-shadow",
                    "shadow",
                    false,
                    Some("http://shadow:14000/v1"),
                    &[],
                ),
            ],
        )
        .expect("fixture snapshot")
    }

    fn kube_state() -> FleetKubeState {
        FleetKubeState {
            node_states: BTreeMap::from([
                ("node-alpha".to_owned(), KubeNodeState::Ready),
                ("node-beta".to_owned(), KubeNodeState::NotReady),
            ]),
            workloads: BTreeMap::from([(
                "node-alpha".to_owned(),
                vec!["job-b".to_owned(), "job-a".to_owned()],
            )]),
        }
    }

    fn probes() -> BTreeMap<String, Reachability> {
        BTreeMap::from([
            ("alpha".to_owned(), Reachability::Reachable),
            ("beta".to_owned(), Reachability::Unreachable),
        ])
    }

    #[test]
    fn project_reports_online_offline_and_preserved_last_seen() {
        let registry = fixture();
        let mut last_seen = BTreeMap::from([(
            "beta".to_owned(),
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(42),
        )]);
        let mut projections = project_fleet(
            &registry,
            &probes(),
            &BTreeMap::new(),
            &kube_state(),
            Some(&FleetSessionCounts { active_sessions: 3 }),
            &mut last_seen,
            &BTreeMap::new(),
            OBSERVED,
        );

        let views: BTreeMap<String, odin_domain::huginn::FleetHostView> = projections
            .iter()
            .filter(|projection| projection.snapshot.object.kind == ObjectKind::FleetHost)
            .map(|projection| {
                (
                    projection.snapshot.object.id.clone(),
                    serde_json::from_value(projection.snapshot.value.clone())
                        .expect("fleet host view"),
                )
            })
            .collect();
        // Exactly the enabled+enrolled declared hosts, iterated from the
        // fixture — no host name is hardcoded in the producer.
        let declared: Vec<String> = ["alpha", "beta"]
            .iter()
            .map(|name| name.to_string())
            .collect();
        let projected: Vec<String> = views.keys().cloned().collect();
        assert_eq!(projected, declared);

        let alpha = &views[&declared[0]];
        assert!(alpha.online);
        assert_eq!(
            alpha.tailnet,
            odin_domain::huginn::FleetTailnetState::Reachable
        );
        assert_eq!(alpha.k3s_node_state, Some(KubeNodeState::Ready));
        assert_eq!(alpha.last_seen, Some(OBSERVED));
        assert_eq!(alpha.pods_scheduled, 2);
        assert_eq!(
            alpha.capabilities,
            vec!["build".to_owned(), "operator".to_owned()]
        );
        assert_eq!(
            alpha.gateway_endpoint.as_deref(),
            Some("http://alpha:14000/v1")
        );
        // The offline host keeps its prior-pass last-seen stamp instead of
        // losing it, and its map entry is preserved untouched.
        let beta = &views[&declared[1]];
        assert!(!beta.online);
        assert_eq!(
            beta.tailnet,
            odin_domain::huginn::FleetTailnetState::Unreachable
        );
        assert_eq!(beta.k3s_node_state, Some(KubeNodeState::NotReady));
        assert_eq!(
            beta.last_seen,
            Some(OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(42))
        );
        assert_eq!(beta.pods_scheduled, 0);
        assert!(beta.authoritative_state);

        let placements: BTreeMap<String, odin_domain::huginn::FleetPlacementView> = projections
            .iter()
            .filter(|projection| projection.snapshot.object.kind == ObjectKind::FleetPlacement)
            .map(|projection| {
                (
                    projection.snapshot.object.id.clone(),
                    serde_json::from_value(projection.snapshot.value.clone())
                        .expect("fleet placement view"),
                )
            })
            .collect();
        // The authority: exactly one, on the declaring node and its host.
        let authority = &placements["fleet:placement:authority"];
        assert_eq!(authority.thing, "odind-authority");
        assert_eq!(authority.node.as_deref(), Some("node-beta"));
        assert_eq!(authority.host.as_deref(), Some("beta"));
        // The host without a k3s node: gateway placement only, k3s state null.
        let gateway = &placements["fleet:placement:gateway:node-alpha"];
        assert_eq!(gateway.thing, "gateway");
        assert_eq!(gateway.endpoint.as_deref(), Some("http://alpha:14000/v1"));
        assert!(!placements.contains_key("fleet:placement:pods:node-beta"));
        let pods = &placements["fleet:placement:pods:node-alpha"];
        assert_eq!(pods.count, Some(2));
        assert_eq!(pods.names, vec!["job-a".to_owned(), "job-b".to_owned()]);
        let sessions = &placements["fleet:placement:seat-sessions"];
        assert_eq!(sessions.host.as_deref(), Some("beta"));
        assert_eq!(sessions.active_count, Some(3));

        // All projection ids are unique and revisions start at one.
        let ids: std::collections::BTreeSet<&str> = projections
            .iter()
            .map(|projection| projection.snapshot.object.id.as_str())
            .collect();
        assert_eq!(ids.len(), projections.len());
        assert!(projections
            .iter()
            .all(|projection| projection.snapshot.revision == Revision::new(1)));

        // A byte-identical pass projects nothing: no revision movement, no
        // downstream rebuild wake.
        let current: BTreeMap<String, ObjectSnapshot> = projections
            .iter()
            .map(|projection| {
                (
                    projection.snapshot.object.id.clone(),
                    projection.snapshot.clone(),
                )
            })
            .collect();
        projections = project_fleet(
            &registry,
            &probes(),
            &BTreeMap::new(),
            &kube_state(),
            Some(&FleetSessionCounts { active_sessions: 3 }),
            &mut last_seen,
            &current,
            OBSERVED,
        );
        assert!(
            projections.is_empty(),
            "unchanged pass must project nothing"
        );

        // Losing both reachability signals moves the host offline and advances its revision.
        let mut flipped = probes();
        flipped.insert("alpha".to_owned(), Reachability::Unreachable);
        let mut offline_kube = kube_state();
        offline_kube
            .node_states
            .insert("node-alpha".to_owned(), KubeNodeState::NotReady);
        projections = project_fleet(
            &registry,
            &flipped,
            &BTreeMap::new(),
            &offline_kube,
            Some(&FleetSessionCounts { active_sessions: 3 }),
            &mut last_seen,
            &current,
            OBSERVED,
        );
        assert_eq!(projections.len(), 1);
        assert_eq!(projections[0].snapshot.object.id, "alpha");
        assert_eq!(projections[0].snapshot.revision, Revision::new(2));
        let alpha = serde_json::from_value::<FleetHostView>(projections[0].snapshot.value.clone())
            .expect("fleet host view");
        // Offline again, but the stamp earned in the online pass survives.
        assert!(!alpha.online);
        assert_eq!(alpha.last_seen, Some(OBSERVED));
    }

    #[test]
    fn session_counts_omit_the_placement_when_no_sessions_exist() {
        use odin_domain::huginn::ObjectSnapshot;

        let capture_object = |id: &str, state: &str| ObjectSnapshot {
            object: ObjectRef {
                kind: ObjectKind::Session,
                id: id.to_owned(),
            },
            revision: Revision::new(1),
            revision_source: odin_domain::huginn::RevisionSource::Omp,
            freshness: Freshness {
                state: FreshnessState::Fresh,
                observed_at: OBSERVED,
                source_updated_at: Some(OBSERVED),
                stale_after_seconds: None,
            },
            content_digest: odin_domain::Digest::hash(state.as_bytes()),
            value: serde_json::json!({ "state": state }),
        };
        let empty = MaterializedReadModel::new(16, OBSERVED);
        let capture = empty.capture().expect("empty capture");
        assert!(FleetSessionCounts::from_capture(&capture).is_none());

        let model = MaterializedReadModel::new(16, OBSERVED);
        model
            .upsert(capture_object("s1", "running"))
            .expect("running session");
        model
            .upsert(capture_object("s2", "idle"))
            .expect("idle session");
        model
            .upsert(capture_object("s3", "ended"))
            .expect("ended session");
        model
            .upsert(capture_object("s4", "failed"))
            .expect("failed session");
        let capture = model.capture().expect("capture");
        let counts = FleetSessionCounts::from_capture(&capture).expect("session counts");
        assert_eq!(counts.active_sessions, 2);
    }

    #[tokio::test]
    async fn tcp_probe_resolves_loopback_listener_and_closed_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let port = listener.local_addr().expect("bound port").port();
        let open = format!("http://127.0.0.1:{port}/v1");
        let started = Instant::now();
        assert_eq!(
            TcpFleetProbe.reachable("fixture", Some(&open)).await,
            Reachability::Reachable
        );
        assert!(started.elapsed() < super::FLEET_PROBE_TIMEOUT);

        // Close the listener, then probe the now-closed port: typed
        // unreachable, returned well inside the bound instead of hanging.
        let closed_port = port;
        drop(listener);
        let closed = format!("http://127.0.0.1:{closed_port}/v1");
        let started = Instant::now();
        assert_eq!(
            TcpFleetProbe.reachable("fixture", Some(&closed)).await,
            Reachability::Unreachable
        );
        assert!(started.elapsed() < super::FLEET_PROBE_TIMEOUT);
    }

    #[tokio::test]
    async fn probe_without_endpoint_is_unknown_and_fanout_is_concurrent() {
        assert_eq!(
            TcpFleetProbe.reachable("fixture", None).await,
            Reachability::Unknown
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let port = listener.local_addr().expect("bound port").port();
        let started = Instant::now();
        let results = super::probe_hosts(
            &TcpFleetProbe,
            [
                (
                    "one".to_owned(),
                    "one".to_owned(),
                    Some(format!("http://127.0.0.1:{port}/v1")),
                ),
                ("two".to_owned(), "two".to_owned(), None),
                (
                    "three".to_owned(),
                    "three".to_owned(),
                    Some("http://127.0.0.1:1/v1".to_owned()),
                ),
            ],
        )
        .await;
        assert!(started.elapsed() < super::FLEET_PROBE_TIMEOUT * 2);
        assert_eq!(results["one"], Reachability::Reachable);
        assert_eq!(results["two"], Reachability::Unknown);
        assert_eq!(results["three"], Reachability::Unreachable);
    }

    /// A deterministic zellij probe: per-host scripted outcomes.
    struct FakeZellij {
        sessions: BTreeMap<String, ZellijSessions>,
    }

    #[async_trait::async_trait]
    impl FleetZellijProbe for FakeZellij {
        async fn sessions(&self, host_tailnet: &str) -> ZellijSessions {
            self.sessions
                .get(host_tailnet)
                .cloned()
                .unwrap_or(ZellijSessions::Unreachable)
        }
    }

    fn zellij_sessions() -> BTreeMap<String, ZellijSessions> {
        BTreeMap::from([
            (
                "alpha".to_owned(),
                ZellijSessions::Live(vec![
                    "odin".to_owned(),
                    "zebra".to_owned(),
                    "odin".to_owned(),
                ]),
            ),
            ("beta".to_owned(), ZellijSessions::Unreachable),
        ])
    }

    #[test]
    fn zellij_sessions_project_live_names_unreachable_and_bounded() {
        let registry = fixture();
        let mut last_seen = BTreeMap::new();
        let mut projections = project_fleet(
            &registry,
            &probes(),
            &zellij_sessions(),
            &kube_state(),
            None,
            &mut last_seen,
            &BTreeMap::new(),
            OBSERVED,
        );

        let placements: BTreeMap<String, odin_domain::huginn::FleetPlacementView> = projections
            .iter()
            .filter(|projection| projection.snapshot.object.kind == ObjectKind::FleetPlacement)
            .filter(|projection| {
                projection
                    .snapshot
                    .object
                    .id
                    .starts_with("fleet:placement:zellij:")
            })
            .map(|projection| {
                (
                    projection.snapshot.object.id.clone(),
                    serde_json::from_value(projection.snapshot.value.clone())
                        .expect("fleet placement view"),
                )
            })
            .collect();

        // A live observation projects the host's sorted, deduplicated
        // session names and live: true.
        let alpha = &placements["fleet:placement:zellij:alpha"];
        assert_eq!(alpha.thing, "zellij-sessions");
        assert_eq!(alpha.host.as_deref(), Some("alpha"));
        assert_eq!(alpha.live, Some(true));
        assert_eq!(alpha.names, vec!["odin".to_owned(), "zebra".to_owned()]);

        // An unreachable observation projects live: false with no names —
        // never a live-looking empty list.
        let beta = &placements["fleet:placement:zellij:beta"];
        assert_eq!(beta.thing, "zellij-sessions");
        assert_eq!(beta.host.as_deref(), Some("beta"));
        assert_eq!(beta.live, Some(false));
        assert!(beta.names.is_empty());

        // The declared host the probe did not cover projects no placement.
        assert!(!placements.contains_key("fleet:placement:zellij:shadow"));

        // Names are bounded to the placement limit: 25 distinct names
        // truncate to exactly the limit, sorted.
        let many: Vec<String> = (0..25).map(|index| format!("sess-{index:02}")).collect();
        let mut zellij = zellij_sessions();
        zellij.insert("alpha".to_owned(), ZellijSessions::Live(many));
        projections = project_fleet(
            &registry,
            &probes(),
            &zellij,
            &kube_state(),
            None,
            &mut last_seen,
            &BTreeMap::new(),
            OBSERVED,
        );
        let bounded: odin_domain::huginn::FleetPlacementView = serde_json::from_value(
            projections
                .iter()
                .find(|projection| projection.snapshot.object.id == "fleet:placement:zellij:alpha")
                .expect("alpha zellij placement")
                .snapshot
                .value
                .clone(),
        )
        .expect("fleet placement view");
        assert_eq!(bounded.names.len(), FLEET_ZELLIJ_NAMES_LIMIT);
        assert_eq!(bounded.names[0], "sess-00");
        assert_eq!(bounded.names[19], "sess-19");

        // A byte-identical pass projects nothing: no revision movement,
        // no downstream rebuild wake.
        let current: BTreeMap<String, ObjectSnapshot> = projections
            .iter()
            .map(|projection| {
                (
                    projection.snapshot.object.id.clone(),
                    projection.snapshot.clone(),
                )
            })
            .collect();
        let mut last_seen = BTreeMap::new();
        projections = project_fleet(
            &registry,
            &probes(),
            &zellij,
            &kube_state(),
            None,
            &mut last_seen,
            &current,
            OBSERVED,
        );
        assert!(
            projections.is_empty(),
            "an unchanged zellij observation must project nothing"
        );
    }

    #[tokio::test]
    async fn zellij_probe_fanout_covers_every_declared_host() {
        let fake = FakeZellij {
            sessions: BTreeMap::from([
                (
                    "alpha".to_owned(),
                    ZellijSessions::Live(vec!["odin".to_owned()]),
                ),
                ("beta".to_owned(), ZellijSessions::Unreachable),
            ]),
        };
        let results = probe_zellij_sessions(
            &fake,
            [
                ("alpha".to_owned(), "alpha".to_owned()),
                ("beta".to_owned(), "beta".to_owned()),
            ],
        )
        .await;
        assert_eq!(
            results["alpha"],
            ZellijSessions::Live(vec!["odin".to_owned()])
        );
        assert_eq!(results["beta"], ZellijSessions::Unreachable);
    }
}
