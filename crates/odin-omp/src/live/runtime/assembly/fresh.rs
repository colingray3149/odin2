use odin_domain::huginn::SessionManifest;

use super::ProductionBridgeRuntimeFactory;
use tracing;

impl ProductionBridgeRuntimeFactory {
    /// Retires `session` and opens a fresh one when the seat's declared
    /// rollover policy says so. The brief is gathered here from the seat's
    /// brain: task notes, `memory.project.*`, and `state.repos`. New
    /// information also carries `owner_text` exactly. The old transcript
    /// stays on the ledger because end does not delete it. A seat with no
    /// fresh bound, and no new information, is left running.
    pub(super) async fn prepare_fresh(
        &self,
        supervisor: &crate::live::supervisor::LiveSupervisor,
        session: odin_domain::huginn::LiveSessionId,
        completed_rollovers: u32,
        new_information: bool,
        owner_text: &str,
    ) -> Result<
        Option<(
            crate::live::rollover::RolloverPolicy,
            crate::live::rollover::FreshBriefSources,
            crate::live::supervisor::FreshPlacement,
        )>,
        odin_domain::huginn::LiveError,
    > {
        use crate::live::rollover::{
            FreshBriefMemory, FreshBriefNote, FreshBriefRepo, FreshBriefSources,
        };
        use crate::live::supervisor::FreshPlacement;
        let Some(summary) = supervisor.durable_summary(session).await? else {
            return Err(odin_domain::huginn::LiveError::NotFound {
                object_kind: "live session".to_owned(),
                object_id: session.to_string(),
            });
        };
        let Some(config) = self.rollover_by_seat.get(&summary.seat_id) else {
            return Ok(None);
        };
        let policy = config.policy();
        if crate::live::rollover::fresh_open_due(&policy, completed_rollovers, new_information)
            .is_none()
        {
            return Ok(None);
        }
        let durable = self
            .live_ledger
            .session(session)
            .await
            .map_err(crate::live::ledger::live_error)?;
        let manifest = durable.manifest;
        let gathered = self
            .brains
            .get(&summary.seat_id)
            .map(|brain| brain.fresh_knowledge(Some(&manifest.project_id)))
            .transpose()
            .map_err(|error| {
                odin_domain::huginn::LiveError::unavailable(
                    "fresh_supervisor_sources",
                    error.to_string(),
                )
            })?
            .unwrap_or_default();
        let mut reason =
            crate::live::rollover::fresh_open_due(&policy, completed_rollovers, new_information)
                .map(|open| open.label())
                .unwrap_or_default();
        if !gathered.unavailable.is_empty() {
            let gaps = format!("sources unavailable: {}", gathered.unavailable.join("; "));
            if reason.is_empty() {
                reason = gaps;
            } else {
                reason = format!("{reason}; {gaps}");
            }
        }
        let sources = FreshBriefSources {
            notes: gathered
                .notes
                .into_iter()
                .map(|note| FreshBriefNote {
                    task: note.task,
                    seat: note.seat,
                    noted_at: note.noted_at,
                    note: note.note,
                })
                .collect(),
            project_memory: gathered
                .project_memory
                .into_iter()
                .map(|entry| FreshBriefMemory {
                    source: entry.source,
                    text: entry.text,
                })
                .collect(),
            repos: gathered
                .repos
                .into_iter()
                .map(|repo| FreshBriefRepo {
                    project: repo.project,
                    summary: repo.summary,
                })
                .collect(),
            reason,
            owner_text: owner_text.to_owned(),
        };
        Ok(Some((
            policy,
            sources,
            FreshPlacement {
                project_id: manifest.project_id,
                slice_id: manifest.slice_id,
                target_node: manifest.target_node,
                open_tab: manifest.open_tab,
                served_revision: manifest.served_revision,
            },
        )))
    }

    /// The seat's core memory, frozen into the session's prompt for the life of the session. An
    /// unreadable memory launches the session with a line saying so instead of refusing it.
    pub(super) fn core_memory(&self, manifest: &SessionManifest) -> Option<String> {
        let brain = self.brains.get(&manifest.seat_id)?;
        let started = std::time::Instant::now();
        match brain.core_memory(Some(&manifest.project_id)) {
            Ok(Some(core)) => {
                let snapshot = odin_domain::Digest::hash(core.text.as_bytes());
                tracing::debug!(
                    "odind: core memory seat={} project={} session={} snapshot={} tokens={} shown={} held={} ms={}",
                    manifest.seat_id.as_str(),
                    manifest.project_id,
                    manifest.session_id,
                    snapshot,
                    core.tokens,
                    core.shown,
                    core.held,
                    started.elapsed().as_millis()
                );
                for line in core.text.lines().filter(|line| line.starts_with("- ")) {
                    tracing::debug!(
                        "odind: core entry seat={} project={} session={} snapshot={} entry={}",
                        manifest.seat_id.as_str(),
                        manifest.project_id,
                        manifest.session_id,
                        snapshot,
                        odin_domain::Digest::hash(line.as_bytes())
                    );
                }
                if let Ok(mut sessions) = self.core_tokens.lock() {
                    sessions.insert(manifest.session_id, core.tokens);
                }
                Some(core.text)
            }
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(
                    "odind: core memory unavailable seat={} project={} error={error}",
                    manifest.seat_id.as_str(),
                    manifest.project_id
                );
                Some(format!(
                    "# Core memory\n(unavailable this session: {error}; brain_search still recalls)"
                ))
            }
        }
    }
}

/// Labels tabs by seat and title, or a short session prefix when no title exists.
pub(super) fn tab_label(manifest: &odin_domain::huginn::SessionManifest) -> String {
    let seat = manifest.seat_id.as_str();
    match manifest
        .title
        .as_deref()
        .map(str::trim)
        .filter(|title| !title.is_empty())
    {
        Some(title) => format!("{seat}-{title}"),
        None => format!(
            "{seat}-{}",
            crate::live::harness::short_session(&manifest.session_id.to_string())
        ),
    }
}
