//! What a loom session needs from the production composition: the same
//! governed session an OMP bridge binds (run, operation binding, admitted
//! tools, scope), its execution proof published at the supervisor's epoch,
//! the system prompt OMP would have been given, and the per-turn brain source.

use super::*;

use odin_ledger::live::NewLiveSession;

#[async_trait]
impl crate::loom::LoomSource for ProductionBridgeRuntimeFactory {
    async fn loom_parts(
        &self,
        manifest: &SessionManifest,
        epoch: odin_domain::huginn::SessionEpoch,
    ) -> Result<crate::loom::LoomParts, LiveError> {
        if !self.allowed_nodes.contains(&manifest.target_node) {
            return Err(LiveError::Unauthorized);
        }
        let project_root = self
            .project_roots
            .get(&manifest.project_id)
            .ok_or_else(|| LiveError::NotFound {
                object_kind: "projectRoot".to_owned(),
                object_id: manifest.project_id.to_string(),
            })?
            .clone();
        let SessionRun {
            bridge_session,
            served_revision,
            material,
            session_lane,
            run_id,
        } = self.session_run(manifest).await?;
        let (binding, admitted, _capsule) = self
            .govern_session(
                manifest,
                &bridge_session,
                served_revision,
                &material,
                &session_lane,
                &project_root,
            )
            .await?;
        let mut bridge = BridgeBinding::new(
            Scope {
                seat: Some(manifest.seat_id.clone()),
                project: Some(manifest.project_id.clone()),
                lane: Some(session_lane.clone()),
                run: Some(run_id.clone()),
                session: Some(bridge_session.clone()),
                ..Scope::default()
            },
            bridge_session.clone(),
            run_id,
            session_lane.clone(),
            format!("{}:{}", self.owner_id, manifest.session_id),
        );
        bridge.epoch = self.publish_loom_binding(manifest, &bridge, epoch)?;
        let declared = self.conversation_guidance.get(&manifest.seat_id);
        let system = [
            declared.map(|declared| declared.text.clone()),
            self.core_memory(manifest),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n\n");
        let hooks: Arc<dyn LiveControlHooks> = Arc::new(FsControlHooks::open(
            &self.hooks_root,
            manifest.session_id,
            manifest.target_node.clone(),
            self.allowed_nodes.clone(),
            Arc::clone(&self.bridge_ledger),
            self.owner_id.to_string(),
        )?);
        Ok(crate::loom::LoomParts {
            operations: self.operations.clone(),
            binding,
            admitted,
            bridge,
            ledger: Arc::clone(&self.bridge_ledger),
            uri_router: self.uri_router.clone(),
            artifact_root: self.artifact_root.clone(),
            context_trace_root: self.context_trace_root.clone(),
            system,
            brain: self.brain_turn_source(manifest, epoch)?,
            images: self.turn_images.clone(),
            children: Arc::new(
                crate::live::runtime::launch_support::BridgeRolloverChildren {
                    links: self.delegation_links.clone(),
                    live: Arc::clone(&self.live_ledger),
                },
            ),
            hooks,
            terminal: self.open_session_terminal(manifest, &project_root).await?,
        })
    }
}

impl ProductionBridgeRuntimeFactory {
    /// Publishes the session's live row at exactly the supervisor's epoch,
    /// as an OMP bridge start does: created when new, moved forward when
    /// behind, refused when ahead (a stale incarnation) or ended.
    fn publish_loom_binding(
        &self,
        manifest: &SessionManifest,
        bridge: &BridgeBinding,
        epoch: odin_domain::huginn::SessionEpoch,
    ) -> Result<i64, LiveError> {
        let epoch = i64::try_from(epoch.get())
            .map_err(|error| invalid(format!("epoch {} does not fit: {error}", epoch.get())))?;
        let mut ledger = self
            .bridge_ledger
            .lock()
            .map_err(|error| LiveError::unavailable("bridge_ledger_lock", error))?;
        let now = time::OffsetDateTime::now_utc();
        let published = match ledger.live_session(&bridge.session_id) {
            Ok(existing) if existing.epoch > epoch => {
                return Err(LiveError::EpochMismatch {
                    expected: crate::live::control::checked_session_epoch(epoch)
                        .map_err(invalid)?,
                    actual: crate::live::control::checked_session_epoch(existing.epoch)
                        .map_err(invalid)?,
                })
            }
            Ok(_) => ledger.reclaim_live_session_to(&bridge.session_id, epoch, now),
            Err(odin_ledger::LedgerError::NotFound { .. }) => ledger.create_live_session_at(
                &NewLiveSession {
                    session_id: bridge.session_id.clone(),
                    seat_id: manifest.seat_id.to_string(),
                    project_id: manifest.project_id.to_string(),
                    slice_id: manifest.slice_id.to_string(),
                    lane_id: bridge.lane_id.to_string(),
                    target_node_id: manifest.target_node.to_string(),
                    provider: manifest.provider.as_str().to_owned(),
                    model: manifest.model.as_str().to_owned(),
                    title: manifest.title.clone(),
                    manifest: serde_json::to_value(manifest).map_err(|error| {
                        invalid(format!("manifest does not serialize: {error}"))
                    })?,
                    open_tab: manifest.open_tab,
                    state: "ready".to_owned(),
                    created_at: now,
                },
                epoch,
            ),
            Err(error) => Err(error),
        };
        match published {
            Ok(row) => Ok(row.epoch),
            Err(odin_ledger::LedgerError::SessionEnded { id }) => Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: format!(
                    "live session {id} is truthfully ended; a terminal session is never reclaimed"
                ),
            }),
            Err(error) => Err(LiveError::unavailable("loom_binding", error)),
        }
    }
}
