//! Conversation seats publish routine declarations through the shared authoring transaction.
//! Routines are read live and excluded from composition digests, so routine-only
//! publications need no daemon reload, vehicle rollover, or deferred delegation.

use odin_hermes::runtime::routines::{RoutineChange, RoutineRoute, RoutineSetRequest};
use odin_registry::schema::{
    RoutineActionKind, RoutineActionToml, RoutineEvent, RoutineSchedule, RoutineToml,
    RoutineTriggerToml,
};
use odin_registry::{ObjectConfig, RegistryKind};

use crate::project_authoring::DaemonProjectRoute;

fn path(id: &str) -> String {
    format!("registry/routines/{id}/routine.toml")
}

impl DaemonProjectRoute {
    fn routine_owner(&self, id: &str) -> Option<odin_domain::SeatId> {
        self.pin
            .current()
            .objects
            .iter()
            .find_map(|object| match &object.config {
                ObjectConfig::Routine(routine) if object.id == id => Some(routine.seat.clone()),
                _ => None,
            })
    }

    fn set_routine(
        &self,
        caller: &odin_domain::SeatId,
        request: &RoutineSetRequest,
    ) -> Result<RoutineChange, String> {
        let id = request.id.as_str();
        if !odin_registry::schema::valid_id(id) {
            return Err(format!("{id:?} is not a routine id like morning-brief"));
        }
        let owner = self.routine_owner(id);
        if owner.as_ref().is_some_and(|owner| owner != caller) {
            return Err(format!("routine {id} belongs to another seat"));
        }
        if let Some(schedule) = &request.schedule {
            RoutineSchedule::parse(schedule)?;
        }
        let event = request
            .event
            .as_deref()
            .map(|event| {
                serde_json::from_value::<RoutineEvent>(serde_json::json!(event))
                    .map_err(|_| format!("{event:?} is not an event a routine can follow"))
            })
            .transpose()?;
        if let Some(event) = event {
            declaration_trigger_check(request, event)?;
        }
        let kind = match request.action.as_str() {
            "brief" => RoutineActionKind::Brief,
            "dm" => RoutineActionKind::Dm,
            other => return Err(format!("action {other:?} is not brief or dm")),
        };
        let declaration = RoutineToml {
            schema: odin_registry::schema::REGISTRY_SCHEMA.to_owned(),
            kind: RegistryKind::Routine,
            enabled: true,
            description: request.description.trim().to_owned(),
            seat: caller.clone(),
            trigger: RoutineTriggerToml {
                schedule: request.schedule.clone(),
                event,
                profile: request.profile.clone(),
                matches: request.matches.clone(),
                lead_minutes: request.lead_minutes,
                account: request.account.clone(),
            },
            action: RoutineActionToml {
                kind,
                text: request.text.trim().to_owned(),
            },
        };
        let text = toml::to_string(&declaration)
            .map_err(|error| format!("routine {id} does not serialize: {error}"))?;
        let outcome = if owner.is_some() {
            "replaced"
        } else {
            "declared"
        };
        let message = format!("routine: {outcome} '{id}' (runtime, by seat {caller})");
        let repo_push = declaration.trigger.event == Some(RoutineEvent::RepoPush);
        let heads_lock = if repo_push {
            Some(crate::live::repo_watch::lock_heads(
                &self
                    .admission_config
                    .paths
                    .state_root
                    .join("repo-heads.json"),
            )?)
        } else {
            None
        };
        if let Some(lock) = &heads_lock {
            crate::live::repo_watch::baseline_published(
                &self.admission_config,
                &self.pin,
                id,
                lock,
            )
            .map_err(|error| format!("routine {id} repository baseline failed: {error}"))?;
        }
        let (published_revision, commit) =
            self.transact(&message, vec![(path(id), text)], Vec::new(), &[])?;
        drop(heads_lock);
        tracing::info!(
            "routine id={id} seat={caller} outcome={outcome} revision={published_revision}"
        );
        Ok(RoutineChange {
            routine: id.to_owned(),
            outcome: outcome.to_owned(),
            published_revision,
            commit,
        })
    }

    fn remove_routine(
        &self,
        caller: &odin_domain::SeatId,
        id: &str,
    ) -> Result<RoutineChange, String> {
        match self.routine_owner(id) {
            None => return Err(format!("there is no routine {id:?}")),
            Some(owner) if &owner != caller => {
                return Err(format!("routine {id} belongs to another seat"))
            }
            Some(_) => {}
        }
        let directory = format!("registry/routines/{id}");
        let message = format!("routine: remove '{id}' (runtime, by seat {caller})");
        let (published_revision, commit) =
            self.transact(&message, Vec::new(), Vec::new(), &[directory])?;
        tracing::info!(
            "routine id={id} seat={caller} outcome=removed revision={published_revision}"
        );
        Ok(RoutineChange {
            routine: id.to_owned(),
            outcome: "removed".to_owned(),
            published_revision,
            commit,
        })
    }
}

/// Validate triggers before commit so the requesting turn receives any refusal.
fn declaration_trigger_check(
    request: &RoutineSetRequest,
    event: RoutineEvent,
) -> Result<(), String> {
    RoutineTriggerToml {
        schedule: None,
        event: Some(event),
        profile: request.profile.clone(),
        matches: request.matches.clone(),
        lead_minutes: request.lead_minutes,
        account: request.account.clone(),
    }
    .check_event(event)
}

impl RoutineRoute for DaemonProjectRoute {
    fn set(
        &self,
        caller: &odin_domain::SeatId,
        request: RoutineSetRequest,
    ) -> Result<RoutineChange, String> {
        crate::project_authoring::blocking(|| self.set_routine(caller, &request))
    }

    fn remove(&self, caller: &odin_domain::SeatId, id: &str) -> Result<RoutineChange, String> {
        crate::project_authoring::blocking(|| self.remove_routine(caller, id))
    }
}
