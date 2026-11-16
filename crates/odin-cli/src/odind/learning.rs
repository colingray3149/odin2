//! The odind brain ports: the pre-IO vault scoping gate and the delegated
//! task review hook. Each is a daemon-owned port over the per-seat brain
//! services and the live-session manifests; live.rs composes them.

use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::{SeatId, SessionId};

/// The pre-write vault scoping gate composed by the daemon: the per-seat
/// brain services plus the durable live-session manifests it resolves the
/// writing session's declared project against.
pub(crate) struct FactoryVaultWriteGate {
    brains: BTreeMap<SeatId, Arc<odin_brain::service::BrainService>>,
    live_ledger: Arc<dyn odin_omp::live::ledger::LiveLedger>,
    generated_namespace: Option<String>,
}

impl FactoryVaultWriteGate {
    pub(crate) fn new(
        brains: BTreeMap<SeatId, Arc<odin_brain::service::BrainService>>,
        live_ledger: Arc<dyn odin_omp::live::ledger::LiveLedger>,
        generated_namespace: Option<String>,
    ) -> Self {
        Self {
            brains,
            live_ledger,
            generated_namespace,
        }
    }
}

/// Before vault IO, require exactly one reachable memory namespace for the
/// session's project and require the destination source id to match it.
impl odin_hermes::vault::VaultWriteGate for FactoryVaultWriteGate {
    fn gate_generated_write(
        &self,
        seat: &SeatId,
        session: &SessionId,
        source_id: &str,
        page_name: &str,
    ) -> Result<(), odin_brain::error::BrainError> {
        let brain =
            self.brains
                .get(seat)
                .ok_or_else(|| odin_brain::error::BrainError::Unavailable {
                    component: "learning",
                    reason: format!(
                        "seat {} serves no brain service; nothing is declared to write",
                        seat.as_str()
                    ),
                })?;
        let live_session = odin_domain::huginn::ids::LiveSessionId::parse(&session.to_string())
            .map_err(|error| odin_brain::error::BrainError::InvalidRequest(error.to_string()))?;
        let project = {
            let resolve = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    odin_brain::error::BrainError::InvalidRequest(error.to_string())
                })?;
            resolve.block_on(async {
                self.live_ledger
                    .session(live_session)
                    .await
                    .map_err(|error| {
                        odin_brain::error::BrainError::InvalidRequest(error.to_string())
                    })
                    .and_then(|record| {
                        if record.manifest.seat_id != *seat {
                            return Err(odin_brain::error::BrainError::InvalidRequest(
                                "vault write seat does not match the durable session".into(),
                            ));
                        }
                        Ok(record.manifest.project_id)
                    })
            })?
        };
        let generated = self.generated_namespace.as_ref().ok_or_else(|| {
            odin_brain::error::BrainError::InvalidRequest(
                "vault generated namespace is not composed".into(),
            )
        })?;
        let projection_root = format!(
            "{generated}/{}/",
            odin_brain::source::silverbullet::RESERVED_KNOWLEDGE_SEGMENT,
        );
        if page_name.starts_with(&projection_root) {
            return Err(odin_brain::error::BrainError::InvalidRequest(
                "generated knowledge pages are owned by the source projection writer".into(),
            ));
        }
        let reserved = format!(
            "{}/",
            odin_brain::source::silverbullet::RESERVED_MEMORY_SEGMENT,
        );
        if let Some(relative) = page_name.strip_prefix(&reserved) {
            // A reserved memory write lands in `memory/<name>/`, where
            // `memory.<name>` is the bound seat's own memory or a memory
            // namespace the session's project declares — and either way one
            // the session's project scope actually serves.
            let name = relative.split('/').next().unwrap_or_default();
            let source = odin_domain::knowledge::AtlasId::new(format!("memory.{name}")).map_err(
                |error| odin_brain::error::BrainError::InvalidRequest(error.to_string()),
            )?;
            let policy = brain.policy();
            let own = name == seat.as_str();
            let project_declared = policy
                .project_memory(&project)
                .is_some_and(|declared| declared.contains(&source));
            if !(own || project_declared)
                || !policy
                    .project_serving_scope(Some(&project))
                    .contains(&source)
            {
                return Err(odin_brain::error::BrainError::InvalidRequest(
                    "reserved memory writes require the bound seat's own memory or the \
                     session project's declared memory source"
                        .into(),
                ));
            }
            return Ok(());
        }
        let declared = brain.policy().project_memory(&project);
        let mut namespaces = declared.iter().flat_map(|set| set.iter());
        match (namespaces.next(), namespaces.next()) {
            // The actual write destination must BE the declared memory: a
            // generated note is confined only when the source it lands in
            // is the one namespace the project declared. A different or
            // ambiguous destination refuses before any IO.
            (Some(namespace), None) if namespace.as_str() == source_id => Ok(()),
            _ => Err(odin_brain::error::BrainError::InvalidRequest(format!(
                "the session's bound project does not declare the actual write source \
                 {source_id:?} as its single reachable project memory namespace"
            ))),
        }
    }

    fn generated_written(
        &self,
        seat: &SeatId,
        session: &SessionId,
        source_id: &str,
        page_name: &str,
    ) -> Result<(), odin_brain::error::BrainError> {
        self.gate_generated_write(seat, session, source_id, page_name)?;
        let own_prefix = format!(
            "{}/",
            odin_brain::source::silverbullet::memory_namespace(seat.as_str())?,
        );
        if page_name.starts_with(&own_prefix) {
            let source = odin_domain::knowledge::AtlasId::new(format!("memory.{seat}")).map_err(
                |error| odin_brain::error::BrainError::InvalidRequest(error.to_string()),
            )?;
            // Shared readers of this explicitly declared source refresh as well.
            for brain in self.brains.values() {
                if brain
                    .policy()
                    .knowledge
                    .as_ref()
                    .is_some_and(|policy| policy.atlas_sources.contains(&source))
                {
                    brain.ensure_source_generation(&source)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/live.rs"]
mod tests;

#[cfg(test)]
mod feeds_provisioning_tests {}
