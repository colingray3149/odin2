//! Outcome projection: the per-instance control state (catalog, journal,
//! bounded delta and event feeds), the applied-command event frame, and the
//! observation/refresh/read paths that project the authoritative cluster
//! into the shared read model.

use odin_domain::huginn::{
    ArtifactRef, CommandOutcome, CommandStatus, HuginnProtocolError, KubeCommand, KubeEventType,
    KubeEventView, ObjectDelta, ObjectKind, ObjectSnapshot, Revision,
};
use odin_domain::{ArtifactId, CommandId, RunId};
use odin_kube::{JobObservation, KubeError};
use time::OffsetDateTime;

use crate::control_core::ControlJournal;
use crate::read_model::{MaterializedReadModel, ReadModelError};

use super::spec::{epoch_millis, event_reason, operation_for, protocol_error};
use super::KubeControl;
use crate::kube::view::{kube_object_id, KubeCatalog, KubeEventViewInput};

/// One applied-command kube event plus its published content reference,
/// ready to travel as a durable kube-events stream frame.
#[derive(Clone, Debug)]
pub struct KubeEventFrame {
    pub event: KubeEventView,
    pub content: ArtifactRef,
}

/// Journal, projection cache, and drained feed for one control instance.
pub(super) struct ControlState {
    pub(super) catalog: KubeCatalog,
    pub(super) journal: ControlJournal,
    pub(super) deltas: Vec<ObjectDelta>,
    pub(super) events: Vec<KubeEventFrame>,
    pub(super) event_counter: u64,
}

impl ControlState {
    fn journal_applied(
        &mut self,
        command_id: &CommandId,
        at: OffsetDateTime,
        reason: &str,
        message: &str,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        let artifact_id = ArtifactId::from_parts(
            "kube-event",
            epoch_millis(at),
            format!("{}-{}", command_id, self.event_counter),
        )
        .map_err(|error| HuginnProtocolError::InvalidRequest {
            code: "kubeEventIdentity".to_string(),
            message: error.to_string(),
        })?;
        let content = self
            .catalog
            .publish_event_message(artifact_id, reason, message)?;
        self.event_counter += 1;
        Ok(content)
    }

    /// Projects one authoritative cluster observation into the read model.
    /// The catalog owns the local monotonic revision ordinal, so this returns
    /// the replace delta exactly when the projected payload changed.
    pub(super) fn ingest(&mut self, observation: &JobObservation) -> Option<ObjectDelta> {
        self.catalog.observe_workload(observation.workload.clone())
    }
}

/// What publishing one kube delta into the read model took, when it was
/// more than a plain apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeltaPublication {
    /// The read model refused the delta for a revision gap (it was at
    /// `from`, the delta started at `delta_from`); the object was replaced
    /// from the catalog's current snapshot at `to`.
    Resynced {
        object_id: String,
        from: Option<Revision>,
        delta_from: Revision,
        to: Revision,
    },
    /// The read model refused the delta and no resync could repair it.
    Refused { object_id: String, reason: String },
}

/// Applies deltas in order, resyncing an object from the catalog when its revisions diverge.
pub fn publish_deltas(
    read_model: &MaterializedReadModel,
    catalog: &KubeCatalog,
    deltas: impl IntoIterator<Item = ObjectDelta>,
) -> Vec<DeltaPublication> {
    let mut notes = Vec::new();
    for delta in deltas {
        let object = delta.object.clone();
        let delta_from = delta.from_revision;
        match read_model.apply(delta) {
            Ok(()) => {}
            Err(
                ReadModelError::DeltaBaseMismatch { .. }
                | ReadModelError::NotFound { .. }
                | ReadModelError::StaleRevision { .. },
            ) => {
                let from = read_model.current_revision(&object).ok().flatten();
                let snapshot = catalog
                    .snapshots(&[object.kind], true)
                    .into_iter()
                    .find(|snapshot| snapshot.object == object);
                match snapshot.map(|snapshot| read_model.upsert(snapshot)) {
                    // Already at the catalog's revision: nothing was lost.
                    Some(Ok(None)) => {}
                    Some(Ok(Some(applied))) => notes.push(DeltaPublication::Resynced {
                        object_id: object.id.clone(),
                        from,
                        delta_from,
                        to: applied.to_revision,
                    }),
                    Some(Err(error)) => notes.push(DeltaPublication::Refused {
                        object_id: object.id.clone(),
                        reason: format!("resync refused: {error}"),
                    }),
                    None => notes.push(DeltaPublication::Refused {
                        object_id: object.id.clone(),
                        reason: "gap and the catalog no longer holds the object".to_owned(),
                    }),
                }
            }
            Err(error) => notes.push(DeltaPublication::Refused {
                object_id: object.id.clone(),
                reason: error.to_string(),
            }),
        }
    }
    notes
}

impl KubeControl {
    /// Publishes buffered deltas first to preserve revision order, resyncing gaps from the catalog.
    pub async fn publish(
        &self,
        read_model: &MaterializedReadModel,
        deltas: impl IntoIterator<Item = ObjectDelta>,
    ) -> Vec<DeltaPublication> {
        let mut state = self.state.lock().await;
        let buffered = std::mem::take(&mut state.deltas);
        publish_deltas(
            read_model,
            &state.catalog,
            buffered.into_iter().chain(deltas),
        )
    }

    pub async fn outcome(&self, command_id: &CommandId) -> Option<CommandOutcome> {
        self.state.lock().await.journal.outcome(command_id).cloned()
    }

    pub async fn drain_statuses(&self) -> Vec<CommandStatus> {
        self.state.lock().await.journal.drain_statuses()
    }

    /// Drains the bounded replace-delta feed accumulated by ingest, create,
    /// summarize, operate, and the pre-gate observation of applied commands;
    /// the daemon applies each delta into the shared read model exactly once.
    pub async fn drain_deltas(&self) -> Vec<ObjectDelta> {
        std::mem::take(&mut self.state.lock().await.deltas)
    }

    /// Drains the bounded kube-events feed accumulated by applied commands;
    /// the daemon publishes each frame exactly once as a durable stream
    /// frame on the shared kube-events stream.
    pub async fn drain_events(&self) -> Vec<KubeEventFrame> {
        std::mem::take(&mut self.state.lock().await.events)
    }

    /// Ingests watch observations. Every observation is stamped through the
    /// reconciler's durable monotonic-ordinal persistence BEFORE it reaches
    /// the catalog, so restarts honor the persisted ordinal.
    pub async fn observe(
        &self,
        observations: Vec<JobObservation>,
    ) -> Result<Vec<ObjectDelta>, HuginnProtocolError> {
        let mut stamped = Vec::with_capacity(observations.len());
        for observation in observations {
            stamped.push(
                self.reconciler
                    .stamp_observation(observation)
                    .map_err(protocol_error)?,
            );
        }
        let mut state = self.state.lock().await;
        Ok(stamped
            .iter()
            .filter_map(|observation| state.ingest(observation))
            .collect())
    }

    /// An observation this authority refused: collects it once when it is
    /// an abandoned orphan Job (see `odin_kube::reconciler` orphans).
    pub async fn collect_orphan(
        &self,
        observation: &JobObservation,
    ) -> Result<odin_kube::OrphanVerdict, KubeError> {
        self.reconciler
            .collect_orphan(observation, OffsetDateTime::now_utc())
            .await
    }

    /// Catalogs node views from the node inventory watch. Every view is
    /// stamped through the reconciler's durable ordinal persistence BEFORE
    /// cataloging; nodes come only from the API server (usage unknown
    /// arrives usage-stale) and are never fabricated.
    pub async fn observe_nodes(
        &self,
        nodes: Vec<odin_domain::huginn::KubeNodeView>,
    ) -> Result<Vec<ObjectDelta>, KubeError> {
        let mut stamped = Vec::with_capacity(nodes.len());
        for node in nodes {
            stamped.push(self.reconciler.stamp_node(node)?);
        }
        let mut state = self.state.lock().await;
        Ok(stamped
            .into_iter()
            .filter_map(|node| state.catalog.observe_node(node))
            .collect())
    }

    /// Materializes read-model snapshots from the projected catalog.
    pub async fn snapshots(
        &self,
        kinds: &[ObjectKind],
        include_stale: bool,
    ) -> Vec<ObjectSnapshot> {
        self.state
            .lock()
            .await
            .catalog
            .snapshots(kinds, include_stale)
    }

    /// Retires every Odin-owned cataloged workload a complete list of the
    /// owned Jobs (`listed`) no longer holds: Terminating + stale, ordinal
    /// bumped — never claimed residue-free; pod-absence settlement stays
    /// behind the StopAuthority.
    pub async fn retire_unlisted(
        &self,
        listed: &[odin_domain::huginn::KubeResourceRef],
    ) -> Vec<ObjectDelta> {
        let reported: Vec<String> = listed.iter().map(kube_object_id).collect();
        self.state
            .lock()
            .await
            .catalog
            .retire_absent_workloads(&reported, OffsetDateTime::now_utc())
    }

    /// Marks one watched Job deletion in the catalog: the API object left,
    /// which is routing truth only — residue claims remain behind the
    /// StopAuthority's authoritative pod-absence settlement.
    pub async fn retire(
        &self,
        resource: odin_domain::huginn::KubeResourceRef,
    ) -> Result<Option<ObjectDelta>, HuginnProtocolError> {
        let mut state = self.state.lock().await;
        Ok(state
            .catalog
            .retire_workload(&resource, OffsetDateTime::now_utc()))
    }

    /// Replaces placeholder revisions with persisted ordinals before publishing foreign workloads.
    /// Complete lists retire missing views; these observations never permit mutations.
    pub async fn apply_foreign(
        &self,
        event: odin_kube::watch::ForeignEvent,
    ) -> Result<Vec<ObjectDelta>, KubeError> {
        use odin_kube::watch::ForeignEvent;
        let now = OffsetDateTime::now_utc();
        let (views, listed) = match event {
            ForeignEvent::Gone(resource) => {
                let mut state = self.state.lock().await;
                return Ok(state
                    .catalog
                    .retire_foreign_workload(&resource, now)
                    .into_iter()
                    .collect());
            }
            ForeignEvent::Applied(view) => (vec![*view], false),
            ForeignEvent::Listed(views) => (views, true),
        };
        let mut stamped = Vec::with_capacity(views.len());
        for view in views {
            stamped.push(self.reconciler.stamp_foreign(view)?);
        }
        let reported: Vec<String> = stamped
            .iter()
            .map(|view| kube_object_id(&view.resource))
            .collect();
        let mut state = self.state.lock().await;
        let mut deltas: Vec<ObjectDelta> = stamped
            .into_iter()
            .filter_map(|view| state.catalog.observe_workload(view))
            .collect();
        if listed {
            deltas.extend(
                state
                    .catalog
                    .retire_absent_foreign_workloads(&reported, now),
            );
        }
        Ok(deltas)
    }

    /// `kube.health.read`: one bounded, pure read of live cluster health
    /// (node readiness and pressure, pods with observed problems, recent
    /// warning events) straight off the placement client. It never touches
    /// the shared read model or the reconciler and never mutates: the
    /// observation is exactly what the API server returned, or the typed
    /// [`KubeError`] when the scan could not complete.
    pub async fn cluster_health(
        &self,
    ) -> Result<odin_domain::huginn::KubeClusterHealth, KubeError> {
        odin_kube::health::cluster_health(&self.placement).await
    }

    /// Pure read of one run's owned workload. Never mutates the cluster;
    /// the observation is projected so summarize reflects the shared read
    /// model, and any advance emits the usual replace delta.
    pub async fn summarize(
        &self,
        run_id: &RunId,
    ) -> Result<Option<JobObservation>, HuginnProtocolError> {
        let observation = self
            .reconciler
            .observe_run(run_id)
            .await
            .map_err(protocol_error)?;
        let Some(mut observation) = observation else {
            return Ok(None);
        };
        let mut state = self.state.lock().await;
        if let Some(delta) = state.ingest(&observation) {
            state.deltas.push(delta);
        }
        // First sight registers here, so callers may derive their next
        // expected_revision from this view without burning a journaled
        // RevisionMismatch: the view carries the catalog ordinal.
        if let Some(projected) = state.catalog.workload(&observation.workload.resource) {
            observation.workload.revision = projected.revision;
        }
        drop(state);
        Ok(Some(observation))
    }

    /// Fresh commands always publish a delta and event, even for an unchanged payload.
    /// Replays publish only changed observations; settlement is unaffected.
    pub(super) async fn publish_applied(
        &self,
        command: &KubeCommand,
        observation: &JobObservation,
        command_id: &CommandId,
        at: OffsetDateTime,
        fresh: bool,
    ) -> Result<(), HuginnProtocolError> {
        let (kind, verb) = operation_for(command);
        let message = match command {
            KubeCommand::RehomeWorkload { target_node, .. } => {
                format!("workload rehomed to node {target_node}")
            }
            _ => format!("{verb} applied"),
        };
        let mut state = self.state.lock().await;
        let mut delta = state.ingest(observation);
        if delta.is_none() && fresh {
            delta = state
                .catalog
                .workload(&observation.workload.resource)
                .map(|workload| state.catalog.workload_delta(workload, workload.revision));
        }
        let Some(delta) = delta else {
            // Already-projected replay: the original application published
            // this exact advance, so re-announcing it would duplicate the
            // event; only the pending settlement remains.
            return Ok(());
        };
        let revision = state
            .catalog
            .workload(&observation.workload.resource)
            .map(|workload| workload.revision)
            .unwrap_or_else(|| observation.workload.revision);
        let content = state.journal_applied(command_id, at, event_reason(kind), &message)?;
        let event = state.catalog.event_view(KubeEventViewInput {
            event_artifact_id: content.artifact_id.clone(),
            resource: observation.workload.resource.clone(),
            revision,
            event_type: KubeEventType::Normal,
            reason: event_reason(kind).to_string(),
            message,
            observed_at: at,
        });
        state.catalog.record_event(event.clone());
        state.events.push(KubeEventFrame { event, content });
        state.deltas.push(delta);
        Ok(())
    }
}

#[cfg(test)]
mod publish_tests {
    use super::*;
    use crate::kube::SurfaceArtifacts;
    use odin_domain::huginn::{
        FreshnessState, KubeResourceOwnership, KubeResourceRef, KubeResources, KubeWorkloadState,
        KubeWorkloadView, LiveSessionId, QueryScope, SnapshotQuery,
    };
    use odin_domain::{LaneId, SeatId};
    use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

    fn catalog() -> KubeCatalog {
        KubeCatalog::new(
            SurfaceArtifacts::new(
                LiveSessionId::parse("00000000-0000-4000-8000-0000000000aa").unwrap(),
                LaneId::new("lane.kube").unwrap(),
                NonZeroU64::new(65_536).unwrap(),
                NonZeroU64::new(1_048_576).unwrap(),
            ),
            NonZeroUsize::new(16).unwrap(),
            NonZeroU64::new(16_384).unwrap(),
            NonZeroU64::new(128).unwrap(),
        )
    }

    fn job(revision: u64, state: KubeWorkloadState) -> KubeWorkloadView {
        let at = OffsetDateTime::from_unix_timestamp(1_000 + revision as i64).unwrap();
        KubeWorkloadView {
            resource: KubeResourceRef {
                cluster: "default".to_owned(),
                api_version: "batch/v1".to_owned(),
                kind: "Job".to_owned(),
                namespace: Some("default".to_owned()),
                name: "odin-gpu-vectoradd".to_owned(),
                uid: "gpu-uid".to_owned(),
            },
            profile: None,
            ownership: KubeResourceOwnership::Odin {
                run_id: RunId::new("run-gpu").unwrap(),
                attempt_id: None,
                lane_id: LaneId::new("lane.gpu").unwrap(),
                seat_id: SeatId::new("seat.kubert").unwrap(),
            },
            revision,
            state,
            node_id: None,
            containers: Vec::new(),
            requested: KubeResources::default(),
            limit: KubeResources::default(),
            usage: KubeResources::default(),
            usage_stale: true,
            started_at: Some(at),
            finished_at: matches!(state, KubeWorkloadState::Succeeded).then_some(at),
            observed_at: at,
            stale: false,
        }
    }

    #[test]
    fn a_missed_delta_resyncs_and_the_terminal_state_lands() {
        let read_model =
            MaterializedReadModel::with_limits(1_024, 4_096, OffsetDateTime::UNIX_EPOCH);
        let mut catalog = catalog();
        let first = catalog
            .observe_workload(job(4, KubeWorkloadState::Pending))
            .expect("first delta");
        assert!(publish_deltas(&read_model, &catalog, [first.clone()]).is_empty());
        // The delta to 5 is produced and never published (the lost one).
        let _missed = catalog
            .observe_workload(job(5, KubeWorkloadState::Running))
            .expect("missed delta");
        let terminal = catalog
            .observe_workload(job(6, KubeWorkloadState::Succeeded))
            .expect("terminal delta");
        let notes = publish_deltas(&read_model, &catalog, [terminal]);
        assert_eq!(
            notes,
            vec![DeltaPublication::Resynced {
                object_id: first.object.id.clone(),
                from: Some(Revision::new(4)),
                delta_from: Revision::new(5),
                to: Revision::new(6),
            }]
        );
        let shown = read_model.get(&first.object).unwrap().expect("object");
        assert_eq!(shown.revision, Revision::new(6));
        assert_eq!(shown.value["state"], "succeeded", "{}", shown.value);
    }

    /// Usage staleness does not hide a Job; only its departure tombstone does.
    #[test]
    fn usage_stale_job_stays_visible_and_tombstone_stays_hidden() {
        use k8s_openapi::api::batch::v1;

        let job = v1::Job {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("someone-elses-job".to_owned()),
                namespace: Some("other".to_owned()),
                uid: Some("12345678-90ab-cdef-1234-567890abcdef".to_owned()),
                ..Default::default()
            },
            spec: Some(v1::JobSpec::default()),
            ..Default::default()
        };
        let view = odin_kube::status::observe_foreign_job("prod", &job, 4);
        assert!(view.usage_stale);
        assert!(!view.stale);

        let mut catalog = catalog();
        let delta = catalog
            .observe_workload(view.clone())
            .expect("the first observation publishes a delta");
        let read_model =
            MaterializedReadModel::with_limits(1_024, 4_096, OffsetDateTime::UNIX_EPOCH);
        assert!(publish_deltas(&read_model, &catalog, [delta]).is_empty());

        let default_page = |include_stale: bool| {
            read_model
                .snapshot_page(SnapshotQuery {
                    scope: QueryScope::All,
                    kinds: vec![ObjectKind::KubeResource],
                    if_revision: None,
                    cursor: None,
                    limit: NonZeroU16::new(64).expect("limit"),
                    include_stale,
                })
                .expect("snapshot page")
        };
        let id = kube_object_id(&view.resource);
        let listed = default_page(false)
            .objects
            .into_iter()
            .find(|snapshot| snapshot.object.id == id)
            .expect("usage-stale Job must stay in the default listing");
        assert_eq!(listed.freshness.state, FreshnessState::Fresh);
        assert_eq!(listed.value["stale"], false);
        assert_eq!(listed.value["usageStale"], true);

        // The object leaves the API: the foreign mirror retires its view.
        let gone = catalog
            .retire_foreign_workload(&view.resource, OffsetDateTime::UNIX_EPOCH)
            .expect("retirement publishes a delta");
        assert!(publish_deltas(&read_model, &catalog, [gone]).is_empty());

        assert!(default_page(false)
            .objects
            .iter()
            .all(|snapshot| snapshot.object.id != id));
        let tombstone = default_page(true)
            .objects
            .into_iter()
            .find(|snapshot| snapshot.object.id == id)
            .expect("the tombstone stays reachable with include_stale");
        assert_eq!(tombstone.freshness.state, FreshnessState::Stale);
    }
}
