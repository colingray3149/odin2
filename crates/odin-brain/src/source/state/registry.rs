//! The registry state source: one deterministic brain projection of the
//! published `odin-registry` snapshot.
//!
//! The authoritative handle is the runtime [`SnapshotHandle`]: validated at
//! open, swapped atomically as a complete `Arc` on reload, and pinned per
//! request through [`SnapshotHandle::current`]. This source never caches a
//! snapshot across pins — every [`RegistrySource::pin`] re-pins `current()`,
//! so a `watch::Receiver<u64>` over the handle's revision (the daemon's
//! head-event hook) is the only notification it needs: the next pin after a
//! swap observes the new revision, which uniquely identifies immutable content.
//!
//! Deterministic, declaration-derived projection:
//! - One [`SourceItem`] per declared seat, slice, project, lane, and
//!   capability under the stable natural keys `seat/<id>`, `slice/<id>`,
//!   `project/<id>`, `lane/<id>`, `capability/<id>`, at
//!   [`TrustClass::Curated`] (authored declaration, not runtime observation).
//! - The head digest binds the pinned snapshot's schema, revision, and
//!   published hash; every item of one pin carries exactly that head as its
//!   `source_revision`, so citations and stale checks flow through the
//!   unchanged index path.
//! - The per-seat who-can-do-what section states *published declaration
//!   eligibility*: the registry-declarable portion of
//!   `odin_kernel::policy::effective`. A capability is eligible for
//!   a seat bound to a slice only when the seat declares it in `tool_refs`
//!   AND the slice declares it in `capabilities` AND the seat, the slice, and
//!   the capability are all enabled AND the capability is implemented AND the
//!   capability's `seat_tags` admit one of the seat's categories (or `*`).
//!   Mere membership in either list never asserts effectiveness. Runtime-only
//!   surfaces (adapter health, live denials, resource constraints, the plan
//!   gate) are session state, not published declarations, and are never
//!   claimed here; the daemon composition binds project/lane capability sets
//!   to the slice's declared set, so the slice declaration is the exact
//!   published authority this source can state.
//! - Summaries are selective: identities, enabled flags, handlers, and
//!   declared relations only. No budgets, limits, credentials, endpoints, or
//!   full configuration dumps.
//!
//! Errors fail closed: every fallible step propagates; nothing is silently
//! skipped or defaulted.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use odin_domain::knowledge::ids::AtlasId;
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::Digest;
use odin_registry::schema::{
    CapabilityToml, HandlerBindingToml, LaneToml, ProjectToml, SeatToml, SliceToml,
};
use odin_registry::{ObjectConfig, RegistryObject, Snapshot, SnapshotHandle};

use crate::error::BrainResult;
use crate::source::SourceItem;

/// Domain-separation prefix for the head digest material.
const HEAD_DOMAIN: &[u8] = b"odin-brain:registry-head:v1\x00";

/// The brain source over the published registry snapshot.
///
/// [`Clone`] shares the runtime handle (`Arc`): clones observe the same
/// swapped revisions; no snapshot authority is ever copied.
#[derive(Clone)]
pub struct RegistrySource {
    atlas_id: AtlasId,
    snapshots: Arc<SnapshotHandle>,
}

impl RegistrySource {
    /// Binds this source to one knowledge-source identity and the runtime
    /// snapshot handle. The handle stays the sole authority; the source only
    /// reads through it.
    pub const fn new(atlas_id: AtlasId, snapshots: Arc<SnapshotHandle>) -> Self {
        Self {
            atlas_id,
            snapshots,
        }
    }

    /// The knowledge source identity used for items and citations.
    pub const fn atlas_id(&self) -> &AtlasId {
        &self.atlas_id
    }

    /// Pins the current verified snapshot and projects it into the head
    /// digest plus the full item set. Each call re-pins `current()`, so the
    /// result always reflects the newest swapped revision.
    pub fn pin(&self) -> BrainResult<(Digest, Vec<SourceItem>)> {
        let snapshot = self.snapshots.current();
        let head = head_digest(&snapshot);
        let items = project_items(&self.atlas_id, &snapshot, head)?;
        Ok((head, items))
    }
}

/// Manual [`Debug`]: the authority handle carries no debug contract, so only
/// the identity is shown.
impl fmt::Debug for RegistrySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrySource")
            .field("atlas_id", &self.atlas_id)
            .finish_non_exhaustive()
    }
}

/// The head digest binds schema, revision, and published hash — the exact
/// identity of the pinned declaration world.
fn head_digest(snapshot: &Snapshot) -> Digest {
    let mut material = Vec::with_capacity(HEAD_DOMAIN.len() + snapshot.schema.len() + 64);
    material.extend_from_slice(HEAD_DOMAIN);
    material.extend_from_slice(snapshot.schema.as_bytes());
    material.push(0);
    material.extend_from_slice(snapshot.revision.to_string().as_bytes());
    material.push(0);
    material.extend_from_slice(snapshot.hash.as_bytes());
    Digest::hash(&material)
}

/// Projects every declared seat, slice, project, lane, and capability of the
/// pinned snapshot into one item each, in fixed kind order and sorted id
/// order within each kind.
fn project_items(
    atlas_id: &AtlasId,
    snapshot: &Snapshot,
    head: Digest,
) -> BrainResult<Vec<SourceItem>> {
    // One pass per projected kind; BTreeMap yields sorted id order, and the
    // per-kind match rejects every other kind, including all runtime kinds
    // (nodes, providers, containers, hosts, workloads) whose configuration is
    // placement and credentials-adjacent policy, not knowledge surface.
    let seat_decls: BTreeMap<&str, &SeatToml> = decl_map(&snapshot.objects);
    let slice_decls: BTreeMap<&str, &SliceToml> = decl_map(&snapshot.objects);
    let project_decls: BTreeMap<&str, &ProjectToml> = decl_map(&snapshot.objects);
    let lane_decls: BTreeMap<&str, &LaneToml> = decl_map(&snapshot.objects);
    let capability_decls: BTreeMap<&str, &CapabilityToml> = decl_map(&snapshot.objects);

    let mut items = Vec::new();
    for (id, seat) in &seat_decls {
        items.push(item(
            atlas_id,
            head,
            format!("seat/{id}"),
            seat_text(id, seat, &slice_decls, &capability_decls),
        )?);
    }
    for (id, slice) in &slice_decls {
        items.push(item(
            atlas_id,
            head,
            format!("slice/{id}"),
            slice_text(id, slice),
        )?);
    }
    for (id, project) in &project_decls {
        items.push(item(
            atlas_id,
            head,
            format!("project/{id}"),
            project_text(id, project),
        )?);
    }
    for (id, lane) in &lane_decls {
        items.push(item(
            atlas_id,
            head,
            format!("lane/{id}"),
            lane_text(id, lane),
        )?);
    }
    for (id, capability) in &capability_decls {
        items.push(item(
            atlas_id,
            head,
            format!("capability/{id}"),
            capability_text(id, capability),
        )?);
    }
    Ok(items)
}

/// Kind-directed view of one registry object's typed declaration.
trait DeclOf<Value> {
    fn decl(&self) -> Option<&Value>;
}

impl DeclOf<SeatToml> for ObjectConfig {
    fn decl(&self) -> Option<&SeatToml> {
        match self {
            ObjectConfig::Seat(value) => Some(value.as_ref()),
            _ => None,
        }
    }
}

impl DeclOf<SliceToml> for ObjectConfig {
    fn decl(&self) -> Option<&SliceToml> {
        match self {
            ObjectConfig::Slice(value) => Some(value.as_ref()),
            _ => None,
        }
    }
}

impl DeclOf<ProjectToml> for ObjectConfig {
    fn decl(&self) -> Option<&ProjectToml> {
        match self {
            ObjectConfig::Project(value) => Some(value.as_ref()),
            _ => None,
        }
    }
}

impl DeclOf<LaneToml> for ObjectConfig {
    fn decl(&self) -> Option<&LaneToml> {
        match self {
            ObjectConfig::Lane(value) => Some(value.as_ref()),
            _ => None,
        }
    }
}

impl DeclOf<CapabilityToml> for ObjectConfig {
    fn decl(&self) -> Option<&CapabilityToml> {
        match self {
            ObjectConfig::Capability(value) => Some(value.as_ref()),
            _ => None,
        }
    }
}

/// Collects one projected kind's declarations, keyed by registry id in
/// sorted order.
fn decl_map<Value>(objects: &[RegistryObject]) -> BTreeMap<&str, &Value>
where
    ObjectConfig: DeclOf<Value>,
{
    objects
        .iter()
        .filter_map(|object| {
            object
                .config
                .decl()
                .map(|value| (object.id.as_str(), value))
        })
        .collect()
}

fn item(atlas_id: &AtlasId, head: Digest, key: String, text: String) -> BrainResult<SourceItem> {
    SourceItem::new(
        atlas_id.clone(),
        head,
        key.as_bytes(),
        TrustClass::Curated,
        text,
    )
}

/// Declared capability references of one seat joined in sorted order.
fn joined<'a, I>(values: I) -> String
where
    I: IntoIterator<Item = &'a str>,
{
    let mut names: Vec<&str> = values.into_iter().collect();
    names.sort_unstable();
    names.join(", ")
}

/// Declaration eligibility requires enabled, implemented, category-admitted
/// capabilities present in both seat and slice; runtime conditions are separate.
fn declared_effective_capabilities<'a>(
    seat: &SeatToml,
    slice: &'a SliceToml,
    capabilities: &BTreeMap<&'a str, &'a CapabilityToml>,
) -> Vec<&'a str> {
    if !seat.enabled || !slice.enabled {
        return Vec::new();
    }
    slice
        .capabilities
        .iter()
        .filter(|declared| seat.tool_refs.contains(*declared))
        .filter(|declared| {
            capabilities
                .get(declared.as_str())
                .is_some_and(|capability| {
                    capability.enabled
                        && capability.is_implemented()
                        && (capability.seat_tags.contains("*")
                            || !capability.seat_tags.is_disjoint(&seat.categories))
                })
        })
        .map(|declared| declared.as_str())
        .collect()
}

fn seat_text(
    id: &str,
    seat: &SeatToml,
    slices: &BTreeMap<&str, &SliceToml>,
    capabilities: &BTreeMap<&str, &CapabilityToml>,
) -> String {
    let mut lines = vec![
        format!("registry seat {id}"),
        format!("description: {}", seat.description),
        format!("enabled: {}", seat.enabled),
        format!(
            "categories: {}",
            joined(seat.categories.iter().map(String::as_str))
        ),
        format!(
            "project scope: {}",
            joined(seat.project_scope.iter().map(|scope| scope.as_str()))
        ),
        format!(
            "brain scope: {}",
            joined(seat.brain_scope.iter().map(|scope| scope.as_str()))
        ),
        format!(
            "tool refs: {}",
            joined(seat.tool_refs.iter().map(|reference| reference.as_str()))
        ),
    ];
    if let Some(live) = &seat.live {
        lines.push(format!(
            "live lanes: file in {}, file out {}, render in {}, render out {}",
            live.file_ingress_lane.as_str(),
            live.file_egress_lane.as_str(),
            live.render_ingress_lane.as_str(),
            live.render_egress_lane.as_str(),
        ));
    }
    if let Some(conversation) = &seat.conversation {
        lines.push(format!(
            "standing conversation: project {}, ask capability {}",
            conversation.project.as_str(),
            conversation.ask_capability.as_str(),
        ));
    }
    lines.push(
        "declared who-can-do-what (eligibility if bound to each slice; \
         not a live session grant)"
            .to_owned(),
    );
    if slices.is_empty() {
        lines.push("  (no slices declared)".to_owned());
    }
    for (slice_id, slice) in slices {
        if !slice.enabled || !seat.enabled {
            lines.push(format!(
                "  slice {slice_id}: disabled or seat disabled; grants nothing"
            ));
            continue;
        }
        let effective = declared_effective_capabilities(seat, slice, capabilities);
        if effective.is_empty() {
            lines.push(format!(
                "  slice {slice_id}: no declared effective capabilities"
            ));
        } else {
            lines.push(format!("  slice {slice_id}: {}", effective.join(", ")));
        }
    }
    lines.join("\n")
}

fn slice_text(id: &str, slice: &SliceToml) -> String {
    let mut lines = vec![
        format!("registry slice {id}"),
        format!("description: {}", slice.description),
        format!("enabled: {}", slice.enabled),
        format!(
            "declared capabilities: {}",
            joined(
                slice
                    .capabilities
                    .iter()
                    .map(|capability| capability.as_str())
            )
        ),
    ];
    if let Some(knowledge) = &slice.knowledge {
        lines.push(format!(
            "knowledge sources: {}",
            joined(knowledge.atlas_sources.iter().map(|source| source.as_str()))
        ));
    }
    lines.join("\n")
}

fn project_text(id: &str, project: &ProjectToml) -> String {
    let mut lines = vec![
        format!("registry project {id}"),
        format!("description: {}", project.description),
        format!("enabled: {}", project.enabled),
        format!("default seat: {}", project.default_seat.as_str()),
        format!(
            "memory namespaces: {}",
            joined(
                project
                    .memory_namespaces
                    .iter()
                    .map(|namespace| namespace.as_str())
            )
        ),
    ];
    if !project.source_root.is_empty() {
        lines.push(format!("source root: {}", project.source_root));
    }
    lines.join("\n")
}

fn lane_text(id: &str, lane: &LaneToml) -> String {
    let mut lines = vec![
        format!("registry lane {id}"),
        format!("description: {}", lane.description),
        format!("enabled: {}", lane.enabled),
        format!("project: {}", lane.project.as_str()),
        format!("family: {}", lane.family),
        format!("default seat: {}", lane.default_seat.as_str()),
        format!("queue: {}", lane.queue),
        format!(
            "independent review required: {}",
            lane.requires_independent_review
        ),
    ];
    if let Some(transfer) = lane.transfer_policy() {
        lines.push(format!(
            "transfer: {:?} {:?}",
            transfer.direction, transfer.payload_kind
        ));
    }
    lines.join("\n")
}

fn capability_text(id: &str, capability: &CapabilityToml) -> String {
    let handler = match &capability.handler {
        Some(HandlerBindingToml::Builtin(builtin)) => format!("builtin:{}", builtin.id),
        Some(HandlerBindingToml::Exec(exec)) => format!("exec:{}", exec.executable),
        None => "none".to_owned(),
    };
    let mut lines = vec![
        format!("registry capability {id}"),
        format!("description: {}", capability.description),
        format!("enabled: {}", capability.enabled),
        format!("implemented: {}", capability.is_implemented()),
        format!("effect class: {:?}", capability.effect_class),
        format!("approval policy: {:?}", capability.approval_policy),
        format!("idempotency: {:?}", capability.idempotency),
        format!("handler: {handler}"),
        format!(
            "seat tags: {}",
            joined(capability.seat_tags.iter().map(String::as_str))
        ),
    ];
    if let Some(delegate_to) = &capability.delegate_to {
        lines.push(format!("delegate to seat: {}", delegate_to.as_str()));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    use odin_domain::knowledge::ids::AtlasId;
    use odin_registry::schema::parse_object_toml;
    use odin_registry::{RegistryKind, RegistryObject, Snapshot, SnapshotStore};
    use tempfile::TempDir;

    use super::RegistrySource;

    const SOURCE_ID: &str = "state.registry";

    fn object(kind: RegistryKind, id: &str, source: &str) -> RegistryObject {
        parse_object_toml(
            kind,
            id,
            format!("registry/{}/{id}.toml", kind.directory()),
            source,
        )
        .expect("fixture object parses")
    }

    fn seat(enabled: bool, tool_refs: &str, categories: &str) -> RegistryObject {
        object(
            RegistryKind::Seat,
            "architect",
            &format!(
                r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = {enabled}
description = "Fixture seat"
categories = [{categories}]
tool_refs = [{tool_refs}]
project_scope = ["odin"]
brain_scope = ["atlas.code"]

[approval_defaults]
r0 = "auto"
r1 = "auto"
r2 = "auto"
r3 = "approval"

[limits]
max_parallel_runs = 2
max_sessions = 2
budget = {{ usd_micros = 7_000_000, window = {{ duration_seconds = 60 }} }}
"#
            ),
        )
    }

    fn slice(enabled: bool, capabilities: &str) -> RegistryObject {
        object(
            RegistryKind::Slice,
            "engine",
            &format!(
                r#"
schema = "odin.registry.v1"
kind = "slice"
enabled = {enabled}
description = "Fixture slice"
capabilities = [{capabilities}]
variables = {{}}

[redirects]
out_of_scope = "NeedsPlan"
"#
            ),
        )
    }

    fn project() -> RegistryObject {
        object(
            RegistryKind::Project,
            "odin",
            r#"
schema = "odin.registry.v1"
kind = "project"
enabled = true
description = "Fixture project"
source_root = ""
default_seat = "architect"
memory_namespaces = ["atlas.code"]
artifact_policy = "standard"
"#,
        )
    }

    fn lane() -> RegistryObject {
        object(
            RegistryKind::Lane,
            "architect.file.in",
            r#"
schema = "odin.registry.v1"
kind = "lane"
enabled = true
description = "Fixture lane"
project = "odin"
family = "transfer"
default_seat = "architect"
queue = "interactive"
requires_independent_review = false
direction = "ingress"
payload_kind = "file"
"#,
        )
    }

    /// The fixture capability: `enabled` selects between the reserved
    /// (unimplemented) and the fully implemented declaration.
    fn capability(enabled: bool) -> RegistryObject {
        let extra = if enabled {
            r#"
implementation = "adapter"
handler = { id = "browser_observe" }
input_schema = "schemas/capability/browser.observe.input.json"
output_schema = "schemas/capability/browser.observe.output.json"
evidence_extractor = { id = "browser_evidence" }
seat_tags = ["builder"]
"#
        } else {
            r#"
implementation = "unimplemented"
seat_tags = []
"#
        };
        object(
            RegistryKind::Capability,
            "browser.observe",
            &format!(
                r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = {enabled}
version = 1
description = "Observe a browser surface."
effect_class = "R2"
timeout_seconds = 1
idempotency = "pure"
retry = {{ max_attempts = 0 }}
approval_policy = "none"
{extra}"#
            ),
        )
    }

    fn objects(capability_enabled: bool, slice_enabled: bool) -> Vec<RegistryObject> {
        vec![
            seat(true, "\"browser.observe\", \"context.read\"", "\"builder\""),
            slice(slice_enabled, "\"browser.observe\", \"context.read\""),
            project(),
            lane(),
            capability(capability_enabled),
            context_read(),
        ]
    }

    /// The second fixture capability: always enabled and implemented, so the
    /// eligible-set assertions isolate the `browser.observe` transitions.
    fn context_read() -> RegistryObject {
        object(
            RegistryKind::Capability,
            "context.read",
            r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
version = 1
description = "Read declared project context."
effect_class = "R1"
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 0 }
approval_policy = "none"
implementation = "adapter"
handler = { id = "context_read" }
input_schema = "schemas/capability/context.read.input.json"
output_schema = "schemas/capability/context.read.output.json"
evidence_extractor = { id = "context_evidence" }
seat_tags = ["builder"]
"#,
        )
    }

    /// `SnapshotStore::load_verified` proves: byte-identical active and
    /// versioned snapshot files plus a receipt binding schema, outcome,
    /// revision, and snapshot hash.
    fn publish(root: &Path, snapshot: &Snapshot, previous_revision: Option<u64>) {
        let mut bytes = serde_json::to_vec_pretty(snapshot).expect("serialize snapshot");
        bytes.push(b'\n');
        fs::write(root.join("snapshot.json"), &bytes).expect("write active snapshot");
        let revisions = root.join("revisions");
        fs::create_dir_all(&revisions).expect("create revisions directory");
        let revision = snapshot.revision;
        fs::write(
            revisions.join(format!("{revision:020}.snapshot.json")),
            &bytes,
        )
        .expect("write versioned snapshot");
        let receipt = serde_json::json!({
            "schema": odin_registry::PUBLICATION_RECEIPT_SCHEMA,
            "outcome": "published",
            "revision": revision,
            "previous_revision": previous_revision,
            "commit": format!("commit-{revision}"),
            "tree": format!("tree-{revision}"),
            "snapshot_hash": snapshot.hash.clone(),
        });
        fs::write(
            revisions.join(format!("{revision:020}.receipt.json")),
            serde_json::to_vec_pretty(&receipt).expect("serialize receipt"),
        )
        .expect("write receipt");
    }

    #[test]
    fn stale_head_and_projection_change_across_publications() {
        let temp = TempDir::new().expect("tempdir");
        let store = SnapshotStore::new(temp.path().join("snapshot.json"));
        publish(
            temp.path(),
            &Snapshot::build(1, objects(false, true)).expect("snapshot"),
            None,
        );
        let handle = Arc::new(odin_registry::SnapshotHandle::open(store).expect("handle opens"));
        let source = RegistrySource::new(AtlasId::new(SOURCE_ID).expect("id"), Arc::clone(&handle));

        let (head1, items1) = source.pin().expect("first pin");
        assert_eq!(items1.len(), 6);
        assert!(items1.iter().all(|item| &item.source == source.atlas_id()));
        assert!(items1
            .iter()
            .all(|item| item.trust == odin_domain::knowledge::retrieval::TrustClass::Curated));

        // Natural keys are stable and identity-derived from source plus key.
        let seat_item = items1
            .iter()
            .find(|item| item.text.starts_with("registry seat architect"))
            .expect("seat item");

        // The capability is declared but disabled and unimplemented: its own
        // summary says so, and it is NOT in the seat's who-can-do-what.
        let capability_item = items1
            .iter()
            .find(|item| item.text.starts_with("registry capability browser.observe"))
            .expect("capability item");
        assert!(capability_item.text.contains("enabled: false"));
        assert!(capability_item.text.contains("implemented: false"));
        assert!(capability_item.text.contains("handler: none"));
        let seat_text = &seat_item.text;
        assert!(
            seat_text.contains("  slice engine: context.read"),
            "only the fully eligible capability is effective: {}",
            seat_text
        );
        assert!(!seat_text.contains("slice engine: browser.observe"));

        // Deterministic re-pin without any swap: identical head and items.
        let (head_again, items_again) = source.pin().expect("re-pin");
        assert_eq!(head_again, head1);
        assert_eq!(items_again, items1);

        // Publish revision 2 with the capability enabled and implemented,
        // swap the handle, and re-pin: the head must change and the
        // projections must move with the new publication.
        publish(
            temp.path(),
            &Snapshot::build(2, objects(true, true)).expect("snapshot"),
            Some(1),
        );
        handle.reload().expect("reload advances");
        let (head2, items2) = source.pin().expect("second pin");
        assert_ne!(head2, head1);
        assert!(items2.iter().all(|item| item.source_revision == head2));
        let capability_item2 = items2
            .iter()
            .find(|item| item.text.starts_with("registry capability browser.observe"))
            .expect("capability item");
        assert!(capability_item2.text.contains("enabled: true"));
        assert!(capability_item2.text.contains("implemented: true"));
        assert!(capability_item2
            .text
            .contains("handler: builtin:browser_observe"));
        let seat_item2 = items2
            .iter()
            .find(|item| item.text.starts_with("registry seat architect"))
            .expect("seat item");
        assert!(
            seat_item2
                .text
                .contains("  slice engine: browser.observe, context.read"),
            "the now-implemented capability joins the eligible set: {}",
            seat_item2.text
        );

        // Clone shares the handle: a clone observes the same swapped world.
        let clone = source.clone();
        let (head_clone, _) = clone.pin().expect("clone pin");
        assert_eq!(head_clone, head2);
    }

    #[test]
    fn membership_alone_never_asserts_effectiveness() {
        let temp = TempDir::new().expect("tempdir");
        let store = SnapshotStore::new(temp.path().join("snapshot.json"));
        // The capability is implemented and enabled and appears in BOTH the
        // seat tool_refs and the slice capabilities — but its seat_tags do
        // not admit the seat's categories, so it stays ineffective.
        let mut declared = objects(true, true);
        declared[0] = seat(
            true,
            "\"browser.observe\", \"context.read\"",
            "\"coordinator\"",
        );
        publish(
            temp.path(),
            &Snapshot::build(1, declared).expect("snapshot"),
            None,
        );
        let handle = Arc::new(odin_registry::SnapshotHandle::open(store).expect("handle opens"));
        let source = RegistrySource::new(AtlasId::new(SOURCE_ID).expect("id"), handle);

        let (_, items) = source.pin().expect("pin");
        let seat_item = items
            .iter()
            .find(|item| item.text.starts_with("registry seat architect"))
            .expect("seat item");
        assert!(
            seat_item
                .text
                .contains("  slice engine: no declared effective capabilities"),
            "category rejection must empty the eligible set: {}",
            seat_item.text
        );
        assert!(
            !seat_item.text.contains("slice engine: context.read"),
            "category rejection applies to every capability: {}",
            seat_item.text
        );
        assert!(
            !seat_item.text.contains("slice engine: browser.observe"),
            "membership in tool_refs and capabilities must not leak effectiveness: {}",
            seat_item.text
        );
        // The capability itself is still honestly declared as implemented.
        let capability_item = items
            .iter()
            .find(|item| item.text.starts_with("registry capability browser.observe"))
            .expect("capability item");
        assert!(capability_item.text.contains("implemented: true"));
    }

    #[test]
    fn disabled_slice_grants_nothing_and_summaries_stay_selective() {
        let temp = TempDir::new().expect("tempdir");
        let store = SnapshotStore::new(temp.path().join("snapshot.json"));
        publish(
            temp.path(),
            &Snapshot::build(1, objects(true, false)).expect("snapshot"),
            None,
        );
        let handle = Arc::new(odin_registry::SnapshotHandle::open(store).expect("handle opens"));
        let source = RegistrySource::new(AtlasId::new(SOURCE_ID).expect("id"), handle);

        let (_, items) = source.pin().expect("pin");
        let seat_item = items
            .iter()
            .find(|item| item.text.starts_with("registry seat architect"))
            .expect("seat item");
        assert!(
            seat_item
                .text
                .contains("  slice engine: disabled or seat disabled; grants nothing"),
            "{}",
            seat_item.text
        );
        // Selective template: spend policy and limits never enter summaries.
        assert!(!seat_item.text.contains("usd_micros"));
        assert!(!seat_item.text.contains("budget"));
        assert!(!seat_item.text.contains("max_parallel_runs"));
        // Relations are present.
        assert!(seat_item.text.contains("project scope: odin"));
        let lane_item = items
            .iter()
            .find(|item| item.text.starts_with("registry lane architect.file.in"))
            .expect("lane item");
        assert!(lane_item.text.contains("transfer: Ingress File"));
        let project_item = items
            .iter()
            .find(|item| item.text.starts_with("registry project odin"))
            .expect("project item");
        assert!(project_item.text.contains("default seat: architect"));
        assert!(project_item.text.contains("memory namespaces: atlas.code"));
        let slice_item = items
            .iter()
            .find(|item| item.text.starts_with("registry slice engine"))
            .expect("slice item");
        assert!(slice_item.text.contains("enabled: false"));
    }
}
