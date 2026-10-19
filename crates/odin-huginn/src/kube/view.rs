//! k3s read views: fixture/registered catalog, bounded logs and events, projections.

use std::collections::{BTreeMap, VecDeque};
use std::num::{NonZeroU64, NonZeroUsize};

use super::SurfaceArtifacts;
use odin_domain::huginn::{
    ArtifactKind, ArtifactRef, Freshness, FreshnessState, HuginnProtocolError, KubeEventType,
    KubeEventView, KubeLogView, KubeNodeView, KubeResourceOwnership, KubeResourceRef,
    KubeResourceView, KubeWorkloadState, KubeWorkloadView, ObjectDelta, ObjectDeltaBody,
    ObjectKind, ObjectRef, ObjectSnapshot, Revision, RevisionSource,
};
use odin_domain::{ArtifactId, Digest};
use time::OffsetDateTime;

/// Shared snapshot/delta materializers for the kube, browser, and simulation adapters.
pub use self::builders::{freshness, object_delta, object_snapshot, ObjectDeltaInput};

mod builders {
    //! One snapshot/delta convention per crate: every adapter projection routes through
    //! these constructors so read-model objects carry identical revision/freshness shape.

    use super::{
        Digest, Freshness, FreshnessState, ObjectDelta, ObjectDeltaBody, ObjectKind, ObjectRef,
        ObjectSnapshot, Revision, RevisionSource,
    };
    use serde::Serialize;
    use time::OffsetDateTime;

    /// Digests the canonical compact JSON encoding of `value` by streaming
    /// serialization straight into the BLAKE3 hasher instead of materializing
    /// an intermediate heap `String`. Serializing a `serde_json::Value` into
    /// an infallible `blake3::Hasher` sink cannot fail; an error there is an
    /// invariant violation and must abort loudly, never silently digest a
    /// substitute payload.
    fn canonical_digest(value: &serde_json::Value) -> Digest {
        let mut hasher = blake3::Hasher::new();
        serde_json::to_writer(&mut hasher, value)
            .expect("serializing serde_json::Value into blake3::Hasher cannot fail");
        Digest::new(*hasher.finalize().as_bytes())
    }

    pub fn freshness(observed_at: OffsetDateTime, stale: bool) -> Freshness {
        Freshness {
            state: if stale {
                FreshnessState::Stale
            } else {
                FreshnessState::Fresh
            },
            observed_at,
            source_updated_at: Some(observed_at),
            stale_after_seconds: None,
        }
    }

    pub fn object_snapshot<S: Serialize>(
        kind: ObjectKind,
        id: String,
        revision: Revision,
        revision_source: RevisionSource,
        observed_at: OffsetDateTime,
        stale: bool,
        value: &S,
    ) -> ObjectSnapshot {
        let value = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
        let content_digest = canonical_digest(&value);
        ObjectSnapshot {
            object: ObjectRef { kind, id },
            revision,
            revision_source,
            freshness: freshness(observed_at, stale),
            content_digest,
            value,
        }
    }

    pub struct ObjectDeltaInput<'a, S: Serialize> {
        pub kind: ObjectKind,
        pub id: String,
        pub from_revision: Revision,
        pub to_revision: Revision,
        pub revision_source: RevisionSource,
        pub observed_at: OffsetDateTime,
        pub stale: bool,
        pub value: &'a S,
    }

    pub fn object_delta<S: Serialize>(input: ObjectDeltaInput<'_, S>) -> ObjectDelta {
        ObjectDelta {
            object: ObjectRef {
                kind: input.kind,
                id: input.id,
            },
            from_revision: input.from_revision,
            to_revision: input.to_revision,
            revision_source: input.revision_source,
            freshness: freshness(input.observed_at, input.stale),
            body: ObjectDeltaBody::Replace(
                serde_json::to_value(input.value).unwrap_or(serde_json::Value::Null),
            ),
        }
    }
}

pub fn kube_object_id(resource: &KubeResourceRef) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        resource.cluster,
        resource.kind,
        resource.namespace.as_deref().unwrap_or("-"),
        resource.name,
        resource.uid
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreKubeLogInput<'a> {
    pub resource: KubeResourceRef,
    pub container: Option<String>,
    pub revision: u64,
    pub from: OffsetDateTime,
    pub through: OffsetDateTime,
    pub lines: &'a [String],
    pub log_artifact_id: ArtifactId,
}

pub type StoreLogInput<'a> = StoreKubeLogInput<'a>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubeEventViewInput {
    pub event_artifact_id: ArtifactId,
    pub resource: KubeResourceRef,
    pub revision: u64,
    pub event_type: KubeEventType,
    pub reason: String,
    pub message: String,
    pub observed_at: OffsetDateTime,
}

/// Merged fixture/registered cluster state. Foreign objects are visible exactly as observed and
/// carry [`KubeResourceOwnership::Foreign`]; only Odin-owned workloads are mutable, and only
/// through [`super::control::KubeControl`].
pub struct KubeCatalog {
    artifacts: SurfaceArtifacts,
    nodes: BTreeMap<String, KubeNodeView>,
    workloads: BTreeMap<String, KubeWorkloadView>,
    resources: BTreeMap<String, KubeResourceView>,
    events: VecDeque<KubeEventView>,
    max_events: NonZeroUsize,
    max_log_bytes: NonZeroU64,
    max_log_lines: NonZeroU64,
    evicted_events: u64,
}

impl KubeCatalog {
    pub fn new(
        artifacts: SurfaceArtifacts,
        max_events: NonZeroUsize,
        max_log_bytes: NonZeroU64,
        max_log_lines: NonZeroU64,
    ) -> Self {
        Self {
            artifacts,
            nodes: BTreeMap::new(),
            workloads: BTreeMap::new(),
            resources: BTreeMap::new(),
            events: VecDeque::new(),
            max_events,
            max_log_bytes,
            max_log_lines,
            evicted_events: 0,
        }
    }

    pub fn artifacts(&self) -> &SurfaceArtifacts {
        &self.artifacts
    }

    pub fn evicted_events(&self) -> u64 {
        self.evicted_events
    }

    pub fn register_node(&mut self, view: KubeNodeView) -> Option<u64> {
        self.nodes
            .insert(kube_object_id(&view.resource), view)
            .map(|old| old.revision)
    }

    pub fn register_workload(&mut self, view: KubeWorkloadView) -> Option<u64> {
        self.workloads
            .insert(kube_object_id(&view.resource), view)
            .map(|old| old.revision)
    }

    /// Projects one observed node view (placement reader, core-stamped).
    /// The revision is the reconciler-stamped durable monotonic ordinal, so
    /// the catalog honors the incoming value, refreshes freshness, and
    /// returns a `Replace` delta exactly when the projected payload changed.
    /// Nodes are never fabricated here.
    pub fn observe_node(&mut self, mut view: KubeNodeView) -> Option<ObjectDelta> {
        let id = kube_object_id(&view.resource);
        let (from_revision, changed) = match self.nodes.get(&id) {
            Some(existing) => {
                let mut candidate = view.clone();
                candidate.revision = existing.revision;
                candidate.observed_at = existing.observed_at;
                (existing.revision, candidate != *existing)
            }
            None => (0, true),
        };
        if !changed {
            if let Some(existing) = self.nodes.get_mut(&id) {
                existing.observed_at = existing.observed_at.max(view.observed_at);
            }
            return None;
        }
        if let Some(existing) = self.nodes.get(&id) {
            view.observed_at = existing.observed_at.max(view.observed_at);
        }
        self.nodes.insert(id, view.clone());
        Some(object_delta(ObjectDeltaInput {
            kind: ObjectKind::Node,
            id: kube_object_id(&view.resource),
            from_revision: Revision::new(from_revision),
            to_revision: Revision::new(view.revision),
            revision_source: RevisionSource::Kube,
            observed_at: view.observed_at,
            stale: view.stale,
            value: &view,
        }))
    }

    /// Marks one Odin-owned workload deleted-from-API: state Terminating,
    /// stale, ordinal bumped on the payload change. Routing truth only —
    /// this never claims pod residue is settled. Foreign entries are left
    /// exactly as observed. Absent entries retire nothing.
    pub fn retire_workload(
        &mut self,
        resource: &KubeResourceRef,
        at: OffsetDateTime,
    ) -> Option<ObjectDelta> {
        let id = kube_object_id(resource);
        match self.workloads.get(&id) {
            // The owned retirement path never touches foreign entries: they
            // are absent from the owned enumeration by construction and are
            // reconciled only against the foreign mirror.
            Some(view) if matches!(view.ownership, KubeResourceOwnership::Foreign) => None,
            Some(_) => self.retire_workload_entry(resource, at),
            None => None,
        }
    }

    /// The retirement core shared by the owned and foreign reconcile paths:
    /// state Terminating, stale, ordinal bumped on the payload change.
    /// Routing truth only — this never claims pod residue is settled.
    fn retire_workload_entry(
        &mut self,
        resource: &KubeResourceRef,
        at: OffsetDateTime,
    ) -> Option<ObjectDelta> {
        let id = kube_object_id(resource);
        let next = {
            let existing = self.workloads.get_mut(&id)?;
            if existing.state == KubeWorkloadState::Terminating && existing.stale {
                existing.observed_at = at.max(existing.observed_at);
                return None;
            }
            // The bumped ordinal commits together with the payload mutation
            // below: revision overflow returns `None` before any state/stale
            // write, so a retirement whose delta is never published can
            // never leave the view silently mutated.
            let next = existing.revision.checked_add(1)?;
            existing.state = KubeWorkloadState::Terminating;
            existing.stale = true;
            existing.observed_at = at.max(existing.observed_at);
            existing.revision = next;
            next
        };
        let updated = self.workloads.get(&id)?;
        Some(self.workload_delta(updated, next - 1))
    }

    /// Reconciles the catalog against an authoritative enumeration: every
    /// Odin-owned workload absent from `reported_ids` retires exactly as in
    /// [`Self::retire_workload`]. Returns the union of deltas.
    pub fn retire_absent_workloads(
        &mut self,
        reported_ids: &[String],
        at: OffsetDateTime,
    ) -> Vec<ObjectDelta> {
        let absent: Vec<KubeResourceRef> = self
            .workloads
            .values()
            .filter(|workload| {
                !reported_ids.contains(&kube_object_id(&workload.resource))
                    && !matches!(workload.ownership, KubeResourceOwnership::Foreign)
            })
            .map(|workload| workload.resource.clone())
            .collect();
        absent
            .into_iter()
            .filter_map(|resource| self.retire_workload(&resource, at))
            .collect()
    }

    /// Reconciles the catalog against the authoritative foreign mirror:
    /// every Foreign workload the mirror no longer reports retires exactly
    /// as in `Self::retire_workload_entry` — the object left the API, so
    /// a stale view must not keep claiming Running. Odin-owned entries are
    /// never touched here: the owned watch and relist own their lifecycle.
    pub fn retire_absent_foreign_workloads(
        &mut self,
        reported_ids: &[String],
        at: OffsetDateTime,
    ) -> Vec<ObjectDelta> {
        let absent: Vec<KubeResourceRef> = self
            .workloads
            .values()
            .filter(|workload| {
                matches!(workload.ownership, KubeResourceOwnership::Foreign)
                    && !reported_ids.contains(&kube_object_id(&workload.resource))
            })
            .map(|workload| workload.resource.clone())
            .collect();
        absent
            .into_iter()
            .filter_map(|resource| self.retire_workload_entry(&resource, at))
            .collect()
    }

    /// Retires the cataloged view of `resource` when it is a Foreign one.
    pub fn retire_foreign_workload(
        &mut self,
        resource: &KubeResourceRef,
        at: OffsetDateTime,
    ) -> Option<ObjectDelta> {
        let foreign = self
            .workload(resource)
            .is_some_and(|workload| matches!(workload.ownership, KubeResourceOwnership::Foreign));
        if foreign {
            self.retire_workload_entry(resource, at)
        } else {
            None
        }
    }

    /// Projects one authoritative cluster observation (reconciler or watch)
    /// into the catalog. The revision is the reconciler-stamped durable
    /// monotonic ordinal (persisted authority-side), so the catalog honors
    /// the incoming value — a daemon restart never resets it — refreshes
    /// freshness, and returns a `Replace` delta exactly when the projected
    /// payload changed.
    pub fn observe_workload(&mut self, mut view: KubeWorkloadView) -> Option<ObjectDelta> {
        let id = kube_object_id(&view.resource);
        let (from_revision, changed) = match self.workloads.get(&id) {
            Some(existing) => {
                let mut candidate = view.clone();
                candidate.revision = existing.revision;
                candidate.observed_at = existing.observed_at;
                (existing.revision, candidate != *existing)
            }
            None => (0, true),
        };
        if !changed {
            if let Some(existing) = self.workloads.get_mut(&id) {
                existing.observed_at = existing.observed_at.max(view.observed_at);
            }
            return None;
        }
        if let Some(existing) = self.workloads.get(&id) {
            view.observed_at = existing.observed_at.max(view.observed_at);
        }
        self.workloads.insert(id, view.clone());
        Some(self.workload_delta(&view, from_revision))
    }

    /// One workload view by its exact resource reference.
    pub fn workload(&self, resource: &KubeResourceRef) -> Option<&KubeWorkloadView> {
        self.workloads.get(&kube_object_id(resource))
    }

    pub fn nodes(&self) -> impl Iterator<Item = &KubeNodeView> {
        self.nodes.values()
    }

    /// One observed node view by provider node name (node names are unique
    /// per cluster, so the keyed map is scanned by name).
    pub fn node(&self, name: &str) -> Option<&KubeNodeView> {
        self.nodes.values().find(|node| node.resource.name == name)
    }

    pub fn workloads(&self) -> impl Iterator<Item = &KubeWorkloadView> {
        self.workloads.values()
    }

    pub fn resources(&self) -> impl Iterator<Item = &KubeResourceView> {
        self.resources.values()
    }

    /// Bounded event ring; the oldest event is evicted once the cap is exceeded.
    pub fn record_event(&mut self, event: KubeEventView) {
        self.events.push_back(event);
        while self.events.len() > self.max_events.get() {
            self.events.pop_front();
            self.evicted_events += 1;
        }
    }

    pub fn events(&self) -> impl Iterator<Item = &KubeEventView> {
        self.events.iter()
    }

    /// Stores one bounded log segment outside the read model, truncating to the configured line
    /// and byte caps with `truncated` set.
    pub fn store_log(
        &mut self,
        input: StoreKubeLogInput<'_>,
    ) -> Result<KubeLogView, HuginnProtocolError> {
        let mut kept: Vec<&String> = Vec::with_capacity(input.lines.len());
        let mut bytes = 0_u64;
        let mut truncated = false;
        for line in input.lines {
            let line_len = line.len() as u64;
            if u64::try_from(kept.len()).unwrap_or(u64::MAX) >= self.max_log_lines.get()
                || bytes.saturating_add(line_len) > self.max_log_bytes.get()
            {
                truncated = true;
                break;
            }
            bytes += line_len;
            kept.push(line);
        }
        let mut content = kept
            .iter()
            .map(|line| line.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        content.push('\n');
        let content = self.artifacts.publish(
            input.log_artifact_id,
            ArtifactKind::File,
            "kube-log-segment",
            "text/plain",
            content.as_bytes(),
        )?;
        Ok(KubeLogView {
            resource: input.resource,
            container: input.container,
            revision: input.revision,
            from: input.from,
            through: input.through,
            line_count: kept.len() as u64,
            content,
            truncated,
        })
    }

    /// Materializes snapshot objects for the requested kinds. Events travel as a stream, not as
    /// snapshots.
    pub fn snapshots(&self, kinds: &[ObjectKind], include_stale: bool) -> Vec<ObjectSnapshot> {
        let mut snapshots = Vec::new();
        if kinds.contains(&ObjectKind::Node) {
            for node in self.nodes.values() {
                if include_stale || !node.stale {
                    snapshots.push(object_snapshot(
                        ObjectKind::Node,
                        kube_object_id(&node.resource),
                        Revision::new(node.revision),
                        RevisionSource::Kube,
                        node.observed_at,
                        node.stale,
                        node,
                    ));
                }
            }
        }
        if kinds.contains(&ObjectKind::KubeResource) {
            for workload in self.workloads.values() {
                if include_stale || !workload.stale {
                    snapshots.push(object_snapshot(
                        ObjectKind::KubeResource,
                        kube_object_id(&workload.resource),
                        Revision::new(workload.revision),
                        RevisionSource::Kube,
                        workload.observed_at,
                        workload.stale,
                        workload,
                    ));
                }
            }
            for resource in self.resources.values() {
                if include_stale || !resource.stale {
                    snapshots.push(object_snapshot(
                        ObjectKind::KubeResource,
                        kube_object_id(&resource.resource),
                        Revision::new(resource.revision),
                        RevisionSource::Kube,
                        resource.observed_at,
                        resource.stale,
                        resource,
                    ));
                }
            }
        }
        snapshots
    }

    /// One replace delta for a mutated workload view.
    pub fn workload_delta(&self, workload: &KubeWorkloadView, from_revision: u64) -> ObjectDelta {
        object_delta(ObjectDeltaInput {
            kind: ObjectKind::KubeResource,
            id: kube_object_id(&workload.resource),
            from_revision: Revision::new(from_revision),
            to_revision: Revision::new(workload.revision),
            revision_source: RevisionSource::Kube,
            observed_at: workload.observed_at,
            stale: workload.stale,
            value: workload,
        })
    }

    /// Convenience constructor for adapter-recorded events.
    pub fn event_view(&self, input: KubeEventViewInput) -> KubeEventView {
        KubeEventView {
            event_artifact_id: input.event_artifact_id,
            resource: input.resource,
            revision: input.revision,
            event_type: input.event_type,
            reason: input.reason,
            message: input.message,
            first_observed_at: input.observed_at,
            last_observed_at: input.observed_at,
            count: 1,
        }
    }

    /// Publishes the content-addressed event document and returns its
    /// immutable reference, ready to travel as a stream-frame content.
    pub fn publish_event_message(
        &mut self,
        artifact_id: ArtifactId,
        reason: &str,
        message: &str,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        let document = serde_json::json!({ "reason": reason, "message": message });
        let reference = self.artifacts.publish(
            artifact_id,
            ArtifactKind::File,
            "kube-event",
            "application/json",
            document.to_string().as_bytes(),
        )?;
        Ok(reference)
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU64, NonZeroUsize};

    use odin_domain::huginn::{
        Freshness, FreshnessState, KubeResourceOwnership, KubeResourceRef, KubeResources,
        KubeWorkloadState, KubeWorkloadView, LiveSessionId, ObjectDeltaBody, ObjectKind, ObjectRef,
        Revision, RevisionSource,
    };
    use odin_domain::{Digest, LaneId, RunId, SeatId};
    use serde::{Serialize, Serializer};
    use time::OffsetDateTime;

    use super::builders::object_snapshot;
    use super::{kube_object_id, KubeCatalog, SurfaceArtifacts};

    #[derive(Serialize)]
    struct NestedLeaf {
        zeta: &'static str,
        alpha: u32,
    }

    /// Declaration order deliberately differs from lexical key order at both
    /// nesting levels.
    #[derive(Serialize)]
    struct NestedOutOfOrder {
        omega: NestedLeaf,
        beta: u32,
    }

    #[test]
    fn snapshot_digest_is_canonical_compact_json() {
        let fixture = NestedOutOfOrder {
            omega: NestedLeaf {
                zeta: "last",
                alpha: 1,
            },
            beta: 2,
        };
        let snapshot = object_snapshot(
            ObjectKind::KubeResource,
            "test:object".to_owned(),
            Revision::new(7),
            RevisionSource::Kube,
            OffsetDateTime::UNIX_EPOCH,
            false,
            &fixture,
        );

        // Hash the stored Value's compact bytes, not the source struct's
        // declaration order. This also catches a preserve_order feature change.
        let value = serde_json::to_value(&fixture).unwrap();
        assert_eq!(snapshot.value, value);
        assert_eq!(
            snapshot.content_digest,
            Digest::hash(value.to_string().as_bytes())
        );
        assert_eq!(
            value.to_string(),
            r#"{"beta":2,"omega":{"alpha":1,"zeta":"last"}}"#
        );
    }
    #[test]
    fn snapshot_falls_back_to_null_on_serialization_failure() {
        struct Unserializable;

        impl Serialize for Unserializable {
            fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("unserializable"))
            }
        }

        let snapshot = object_snapshot(
            ObjectKind::KubeResource,
            "test:unserializable".to_owned(),
            Revision::new(1),
            RevisionSource::Kube,
            OffsetDateTime::UNIX_EPOCH,
            false,
            &Unserializable,
        );

        assert_eq!(snapshot.value, serde_json::Value::Null);
        assert_eq!(snapshot.content_digest, Digest::hash(b"null"));
    }

    fn retire_fixture() -> KubeCatalog {
        let session = LiveSessionId::parse("00000000-0000-0000-0000-000000000001").unwrap();
        let artifacts = SurfaceArtifacts::new(
            session,
            LaneId::new("lane.retire").unwrap(),
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(1).unwrap(),
        );
        KubeCatalog::new(
            artifacts,
            NonZeroUsize::new(1).unwrap(),
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
    }

    fn owned_workload(
        suffix: &str,
        revision: u64,
        observed_at: OffsetDateTime,
    ) -> KubeWorkloadView {
        KubeWorkloadView {
            resource: KubeResourceRef {
                cluster: "fixture".to_owned(),
                api_version: "batch/v1".to_owned(),
                kind: "Job".to_owned(),
                namespace: Some("odin".to_owned()),
                name: format!("retire-{suffix}"),
                uid: format!("retire-{suffix}-uid"),
            },
            profile: None,
            ownership: KubeResourceOwnership::Odin {
                run_id: RunId::new("run-retire").unwrap(),
                attempt_id: None,
                lane_id: LaneId::new("lane.retire").unwrap(),
                seat_id: SeatId::new("seat.retire").unwrap(),
            },
            revision,
            state: KubeWorkloadState::Running,
            node_id: None,
            containers: Vec::new(),
            requested: KubeResources::default(),
            limit: KubeResources::default(),
            usage: KubeResources::default(),
            usage_stale: true,
            started_at: Some(observed_at),
            finished_at: None,
            observed_at,
            stale: false,
        }
    }

    #[test]
    fn retire_workload_overflow_returns_none_without_mutating_entry() {
        let registered_at = OffsetDateTime::UNIX_EPOCH;
        let retired_at = OffsetDateTime::from_unix_timestamp(60).unwrap();
        let mut catalog = retire_fixture();
        let saturated = owned_workload("saturated", u64::MAX, registered_at);
        let ordinary = owned_workload("ordinary", 4, registered_at);
        catalog.register_workload(saturated.clone());
        catalog.register_workload(ordinary.clone());

        let delta = catalog
            .retire_workload(&ordinary.resource, retired_at)
            .expect("ordinary retirement must transition the workload");
        assert_eq!(
            delta.object,
            ObjectRef {
                kind: ObjectKind::KubeResource,
                id: kube_object_id(&ordinary.resource),
            }
        );
        assert_eq!(delta.from_revision, Revision::new(4));
        assert_eq!(delta.to_revision, Revision::new(5));
        assert_eq!(delta.revision_source, RevisionSource::Kube);
        assert_eq!(
            delta.freshness,
            Freshness {
                state: FreshnessState::Stale,
                observed_at: retired_at,
                source_updated_at: Some(retired_at),
                stale_after_seconds: None,
            }
        );
        assert!(matches!(delta.body, ObjectDeltaBody::Replace(_)));
        let retired = catalog.workload(&ordinary.resource).unwrap();
        assert_eq!(retired.state, KubeWorkloadState::Terminating);
        assert!(retired.stale);
        assert_eq!(retired.revision, 5);
        assert_eq!(retired.observed_at, retired_at);

        assert_eq!(
            catalog.retire_workload(&saturated.resource, retired_at),
            None
        );
        assert_eq!(catalog.workload(&saturated.resource).unwrap(), &saturated);
    }
}
