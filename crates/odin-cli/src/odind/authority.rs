//! Declared authority composition: the posture-gated operation authority
//! pair, the session-stop coordinator, and the declared conversation
//! authority/binding resolved from the pinned registry.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;

use odin_domain::huginn as live;
use odin_domain::ProjectId;
use odin_huginn::{NodePosture, OdindConfig, RuntimeManifest};
use odin_registry::{ObjectConfig, RegistryObject};

/// Retires the stopping session's private backend when delegation is disabled.
/// The launcher holds this weakly; the serving scope owns its lifetime.
pub(super) struct SessionStopCoordinator(
    pub(super) Arc<crate::live_authority::SessionAuthorityPool>,
);

impl odin_omp::host_tools::delegation::ChildStopCoordinator for SessionStopCoordinator {
    fn await_children_on_stop(
        &self,
        parent: odin_domain::huginn::LiveSessionId,
        budget: StdDuration,
    ) -> Result<Vec<odin_omp::host_tools::delegation::ChildStopRecord>, String> {
        let deadline = std::time::Instant::now() + budget;
        let session = odin_domain::SessionId::new(parent.to_string())
            .map_err(|error| format!("parent session {parent} is invalid: {error}"))?;
        let capsule = odin_omp::host_tools::operations::session_capsule_id(&session)
            .map_err(|error| format!("parent capsule identity is invalid: {error}"))?;
        self.0.retire_session_until(&capsule, deadline)?;
        Ok(Vec::new())
    }
}

/// HMAC verification uses the minting secret, so only authoritative nodes load it;
/// followers receive denied authority objects without key material.
pub(super) fn compose_operation_authority(
    posture: NodePosture,
    config: &OdindConfig,
    manifest: &RuntimeManifest,
) -> Result<
    (
        Arc<odin_omp::host_tools::operations::ProvisionedFreshAuthorityProvider>,
        Arc<crate::live_authority::SessionAuthorityPool>,
    ),
    String,
> {
    match posture {
        NodePosture::Authoritative => {
            let operation_verification_key =
                std::fs::read(&config.paths.authority_verification_key_file).map_err(|error| {
                    format!(
                        "could not read authority verification key file {}: {error}",
                        config.paths.authority_verification_key_file.display()
                    )
                })?;
            if operation_verification_key.len() < 32 {
                return Err(format!(
                    "authority verification key file {} must contain at least 32 bytes",
                    config.paths.authority_verification_key_file.display()
                ));
            }
            let provider = Arc::new(
                odin_omp::host_tools::operations::ProvisionedFreshAuthorityProvider::open(
                    config.paths.authority_token_root.clone(),
                    operation_verification_key.clone(),
                )
                .map_err(|error| error.to_string())?,
            );
            let pool = crate::live_authority::SessionAuthorityPool::open(
                config,
                manifest,
                operation_verification_key,
            )
            .map_err(|error| format!("could not open session authority pool: {error}"))?;
            Ok((provider, pool))
        }
        NodePosture::Follower => {
            tracing::error!(
                "follower posture: authority verification key is not read; \
                 seat-token authority and session capsule minting stay denied"
            );
            Ok((
                Arc::new(
                    odin_omp::host_tools::operations::ProvisionedFreshAuthorityProvider::denying(),
                ),
                crate::live_authority::SessionAuthorityPool::open_denied(config, manifest)?,
            ))
        }
    }
}

pub(super) struct DeclaredConversationAuthority {
    pub(super) config: OdindConfig,
    pub(super) seat: odin_domain::SeatId,
    pub(super) project: ProjectId,
    pub(super) slice: odin_domain::SliceId,
    pub(super) lane: odin_domain::LaneId,
    pub(super) provider: live::ProviderName,
    pub(super) model: live::ModelName,
    /// Where the successor transition's trouble becomes an incident.
    pub(super) incidents: Option<Arc<crate::incidents::IncidentDesk>>,
}

#[async_trait]
impl odin_hermes::conversation::ConversationAuthority for DeclaredConversationAuthority {
    async fn ensure(
        &self,
        command_id: &odin_domain::CommandId,
        session_id: live::LiveSessionId,
    ) -> Result<odin_hermes::conversation::EnsuredGeneration, String> {
        let composition = odin_cli::authority_provision::compose_for_session(
            &self.config,
            self.seat.as_str(),
            self.project.as_str(),
            command_id,
            session_id,
            odin_cli::authority_provision::LaunchSelection::new(
                self.provider.as_str(),
                self.model.as_str(),
            ),
        )?;
        if composition.slice != self.slice || composition.lane != self.lane {
            return Err(format!(
                "registry/seats/{}/seat.toml: published authority differs from the served conversation binding",
                self.seat,
            ));
        }
        let report = match odin_cli::authority_provision::ensure_session_token(
            &self.config,
            &composition,
            odin_cli::authority_provision::DEFAULT_TOKEN_TTL_SECONDS,
            odin_cli::authority_provision::TokenRenewalPolicy::BoundedSameSession,
        ) {
            Ok(report) => report,
            // Start a successor when the session's older generation cannot be recomposed.
            Err(odin_cli::authority_provision::EnsureSessionTokenError::BoundGenerationUnavailable {
                bound,
                detail,
            }) if bound != composition.snapshot_revision => {
                tracing::warn!(
                    "conversation session={session_id} bound generation {bound} is \
                     unrecomposable ({detail}); treating it as lagging revision {}",
                    composition.snapshot_revision
                );
                return Ok(odin_hermes::conversation::EnsuredGeneration {
                    bound,
                    current: composition.snapshot_revision,
                    composition: None,
                });
            }
            Err(error) => return Err(error.to_string()),
        };
        // Renewed tokens retain their original revision; never substitute the current pin.
        let bound = report.served_revision.ok_or_else(|| {
            format!(
                "the installed token for session {} predates revision binding; the conversation \
                 vehicle cannot record a manifest binding the token does not carry — re-open the \
                 session under the current revision",
                composition.session
            )
        })?;
        Ok(odin_hermes::conversation::EnsuredGeneration {
            bound,
            current: composition.snapshot_revision,
            composition: composition_pair(
                &self.config,
                session_id,
                bound,
                composition.snapshot_revision,
            ),
        })
    }

    fn rollover_deferred(&self) -> bool {
        crate::project_authoring::reload_requested()
    }

    fn successor_trouble(
        &self,
        conversation_id: &str,
        trouble: odin_hermes::conversation::SuccessorTrouble,
    ) {
        let Some(desk) = &self.incidents else {
            return;
        };
        // The desk may page the phone over HTTP: off the async worker, in
        // report order.
        let multi_thread = tokio::runtime::Handle::try_current().is_ok_and(|handle| {
            handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread
        });
        if multi_thread {
            tokio::task::block_in_place(|| successor_incident(desk, conversation_id, trouble));
        } else {
            successor_incident(desk, conversation_id, trouble);
        }
    }
}

/// One card per condition: a successor backing off, minting stopped by the
/// cap (which supersedes the backoff card), cleared when one serves. A
/// restated exhaustion (a restart forgot the card) returns it quietly.
fn successor_incident(
    desk: &crate::incidents::IncidentDesk,
    conversation: &str,
    trouble: odin_hermes::conversation::SuccessorTrouble,
) {
    use odin_hermes::conversation::SuccessorTrouble;
    use odin_huginn::incidents::IncidentSeverityView;
    let backoff = format!("vehicle-successor-ended:{conversation}");
    let exhausted = format!("vehicle-successor-exhausted:{conversation}");
    let card =
        |summary: String, detail: String, signature: String| crate::incidents::RaisedIncident {
            source: "odind:vehicle-open".to_owned(),
            severity: IncidentSeverityView::Critical,
            summary,
            detail,
            affected: vec![conversation.to_owned()],
            signature,
        };
    match trouble {
        SuccessorTrouble::Backoff {
            attempts,
            retry_at_unix_ms,
        } => {
            let now_ms =
                u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
                    .unwrap_or(0);
            desk.raise(card(
                format!(
                    "Sinmara's conversation cannot start: {attempts} fresh sessions ended before \
                     serving"
                ),
                format!(
                    "Each new conversation session of {conversation} ended at its first open (the \
                     bridge refused to start). Odin mints the next one in {} s, backing off to \
                     hourly, and stops after {} under this build. The journal names the open \
                     failure.",
                    retry_at_unix_ms.saturating_sub(now_ms) / 1000,
                    odin_hermes::conversation::MAX_ENDED_SUCCESSORS
                ),
                backoff,
            ));
        }
        SuccessorTrouble::Exhausted { attempts, newly } => {
            desk.clear(&backoff, "minting stopped at the cap");
            let incident = card(
                format!(
                    "Sinmara's conversation is down: {attempts} fresh sessions ended before \
                     serving, and Odin stopped trying"
                ),
                format!(
                    "Every new conversation session of {conversation} ended at its first open. \
                     Odin mints no more under this odind build; the journal names the open \
                     failure. Deploying the fix starts it again."
                ),
                exhausted,
            );
            if newly {
                desk.raise(incident);
            } else {
                let _ = desk.restate(incident);
            }
        }
        SuccessorTrouble::Recovered => {
            desk.clear(&backoff, "a conversation successor opened");
            desk.clear(&exhausted, "a conversation successor opened");
        }
    }
}

/// Compare retained composition digests; equal revisions or unavailable digests
/// leave the caller to compare revision numbers alone.
fn composition_pair(
    config: &OdindConfig,
    session: live::LiveSessionId,
    bound: u64,
    current: u64,
) -> Option<odin_hermes::conversation::CompositionPair> {
    if bound == current {
        return None;
    }
    let store = odin_registry::SnapshotStore::new(&config.paths.registry_snapshot);
    let digest = |revision| odin_cli::runtime_bindings::composition_digest_at(&store, revision);
    match (digest(bound), digest(current)) {
        (Ok(bound_digest), Ok(current_digest)) => {
            if bound_digest != current_digest {
                tracing::info!(
                    "conversation session={session} publication composition changed \
                     bound={bound} current={current} digest={bound_digest}->{current_digest}"
                );
            }
            Some(odin_hermes::conversation::CompositionPair {
                bound: bound_digest,
                current: current_digest,
            })
        }
        (left, right) => {
            let error = left.err().or(right.err()).map(|error| error.to_string());
            tracing::error!(
                "conversation session={session} composition digest unproven \
                 bound={bound} current={current} error={error:?}; the bare revision decides"
            );
            None
        }
    }
}

pub(super) struct DeclaredConversationBinding {
    pub(super) ownership: odin_hermes::runtime::ConversationOwnership,
    pub(super) declaration: odin_registry::schema::SeatConversationToml,
    pub(super) vehicle: Option<(
        odin_omp::live::supervisor::LiveSeatBinding,
        odin_domain::LaneId,
    )>,
}

pub(super) fn declared_conversation_binding(
    registry: &[RegistryObject],
    contracts: &BTreeMap<odin_domain::CapabilityId, odin_kernel::CapabilityContract>,
    bindings: &[odin_omp::live::supervisor::LiveSeatBinding],
    lanes: &BTreeMap<(odin_domain::SeatId, ProjectId), odin_domain::LaneId>,
    transport: &odin_hermes::config::DiscordSettings,
    posture: NodePosture,
) -> Result<DeclaredConversationBinding, String> {
    let path = format!("registry/seats/{}/seat.toml", transport.seat);
    let seat = registry
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Seat(seat) if object.id == transport.seat.as_str() && seat.enabled => {
                Some(seat)
            }
            _ => None,
        })
        .ok_or_else(|| format!("{path}: transport seat is absent or disabled"))?;
    let conversation = seat
        .conversation
        .as_ref()
        .ok_or_else(|| format!("{path}: Discord requires an explicit conversation declaration"))?;
    if conversation.project != transport.project {
        return Err(format!(
            "{path}: conversation.project does not match hermes.discord.project"
        ));
    }
    let ask = contracts
        .get(&conversation.ask_capability)
        .ok_or_else(|| format!("{path}: conversation ask capability is not admitted"))?;
    if ask.delegate_to.as_ref() != Some(&transport.seat)
        || ask.effect_class != odin_domain::EffectClass::R3
        || ask.approval != odin_kernel::ApprovalRequirement::Operator
    {
        return Err(format!(
            "{path}: ask capability must be operator-gated and target its declared owner"
        ));
    }
    let vehicle = if posture == NodePosture::Authoritative {
        let binding = bindings
            .iter()
            .find(|binding| binding.seat_id == transport.seat)
            .ok_or_else(|| format!("{path}: conversation seat has no served runtime binding"))?;
        let lane = lanes
            .get(&(transport.seat.clone(), conversation.project.clone()))
            .ok_or_else(|| {
                format!("{path}: no exact session lane for the declared seat and project")
            })?;
        Some((binding.clone(), lane.clone()))
    } else {
        None
    };
    Ok(DeclaredConversationBinding {
        ownership: odin_hermes::runtime::ConversationOwnership {
            seat: transport.seat.clone(),
            project: conversation.project.clone(),
            ask_capability: conversation.ask_capability.clone(),
        },
        declaration: conversation.clone(),
        vehicle,
    })
}

#[cfg(test)]
#[path = "tests/authority.rs"]
mod tests;
