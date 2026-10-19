//! `registry.author` / `registry.author.grant`: a
//! conversation seat fills one of the registry's skeletons from a DM. The
//! skeleton catalog compiles the fill strictly (typed variables, the
//! template's exact shape); the shared authoring transaction then commits it
//! onto odin main, validates the whole candidate registry and publishes it.
//!
//! A watchdog on a pod is `new-alert` naming a `workload` instead of a
//! `container`: it is appended to that profile's `[monitoring]`. A profile is
//! otherwise immutable (a running Job must never change under its pod), but
//! monitoring is read by odind's monitoring kernel, never by the Job, so a
//! new watchdog changes nothing a pod runs — it watches the profile's pods
//! from odind's next idle reload on.

use odin_hermes::runtime::registry_author::{AuthorChange, AuthorRequest, RegistryAuthorRoute};
use odin_registry::schema::{ContainerAlertToml, ObjectConfig, RegistryKind, WorkloadProfileToml};
use odin_registry::{
    AuthoringDestination, AuthoringErrors, CompiledDocument, FillRequest, SkeletonCatalog,
    SkeletonKind,
};
use serde::Deserialize;

use crate::project_authoring::{with_item_in_array, DaemonProjectRoute, Edit};

/// Monitoring cadence a pod profile without `[monitoring]` gets with its
/// first watchdog, unless the fill names one.
const DEFAULT_CADENCE_SECONDS: i64 = 30;

/// The grant-tier edit that turns on a declared capability that is off and
/// grants it to one seat.
const ENABLE_CAPABILITY: &str = "enable-capability";
/// The grant-tier removal verb: one declared environment goes away in one
/// validated, tombstoned commit.
const REMOVE_ENVIRONMENT: &str = "remove-environment";

/// The declared capabilities `enable-capability` can turn on: off, but
/// implemented (an adapter, a builtin or an operator tuple) — never a
/// reserved `unimplemented` contract.
fn capabilities_off(objects: &[odin_registry::RegistryObject]) -> Vec<(String, String)> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Capability(capability)
                if !capability.enabled && implemented(capability.implementation.as_deref()) =>
            {
                Some((object.id.clone(), capability.description.clone()))
            }
            _ => None,
        })
        .collect()
}

fn implemented(implementation: Option<&str>) -> bool {
    implementation.is_some_and(|implementation| implementation != "unimplemented")
}

/// `text` with its top-level `enabled = false` turned to `true`; parsing
/// proves nothing else changed.
fn with_capability_enabled(text: &str) -> Result<String, String> {
    let parse = |text: &str| -> Result<toml::Table, String> {
        toml::from_str(text).map_err(|error| format!("declaration: {error}"))
    };
    let mut expected = parse(text)?;
    match expected.get("enabled") {
        Some(toml::Value::Boolean(false)) => {}
        Some(toml::Value::Boolean(true)) => return Ok(text.to_owned()),
        _ => return Err("the capability declares no enabled flag".to_owned()),
    }
    expected.insert("enabled".to_owned(), toml::Value::Boolean(true));
    let mut edited = String::with_capacity(text.len());
    let mut done = false;
    for line in text.split_inclusive('\n') {
        if !done && line.trim_end() == "enabled = false" {
            edited.push_str(&line.replacen("false", "true", 1));
            done = true;
        } else {
            edited.push_str(line);
        }
    }
    if !done || parse(&edited)? != expected {
        return Err("enabled could not be turned on in place".to_owned());
    }
    Ok(edited)
}

fn skeleton_kind(folder: &str) -> Result<SkeletonKind, String> {
    SkeletonKind::ALL
        .into_iter()
        .find(|kind| kind.folder() == folder)
        .ok_or_else(|| format!("{folder:?} is not a skeleton"))
}

/// One plain line per issue, naming the variable to fix.
fn issues_text(errors: &AuthoringErrors) -> String {
    errors
        .issues
        .iter()
        .map(|issue| match &issue.variable {
            Some(variable) => format!("{variable}: {}", issue.message),
            None => issue.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The pod-watchdog edit: `alert` appended to the profile's
/// `[[monitoring.watchdogs]]` as text (the declaration keeps its own
/// layout), `[monitoring]` opened with `cadence` when the profile has none.
/// Refuses an alert id the profile already declares.
pub(crate) fn append_pod_watchdog(
    source: &str,
    alert: &ContainerAlertToml,
    cadence: i64,
) -> Result<String, String> {
    let profile: WorkloadProfileToml = toml::from_str(source)
        .map_err(|error| format!("the pod profile does not parse: {error}"))?;
    let mut text = source.trim_end().to_owned();
    text.push('\n');
    match &profile.monitoring {
        Some(monitoring) if monitoring.watchdogs.iter().any(|w| w.id == alert.id) => {
            return Err(format!(
                "the pod profile already has a watchdog {}",
                alert.id
            ));
        }
        Some(_) => {}
        None => text.push_str(&format!("\n[monitoring]\ncadence_seconds = {cadence}\n")),
    }
    let body = toml::to_string(alert).map_err(|error| format!("watchdog: {error}"))?;
    text.push_str("\n[[monitoring.watchdogs]]\n");
    text.push_str(&body);
    let patched: WorkloadProfileToml = toml::from_str(&text)
        .map_err(|error| format!("the patched pod profile does not parse: {error}"))?;
    let declared = patched
        .monitoring
        .as_ref()
        .is_some_and(|monitoring| monitoring.watchdogs.last() == Some(alert));
    if !declared {
        return Err("the watchdog did not land in the profile's monitoring".to_owned());
    }
    Ok(text)
}

impl DaemonProjectRoute {
    fn catalog(&self) -> Result<SkeletonCatalog, String> {
        self.sync
            .ensure(&self.worktree)
            .map_err(|failure| failure.to_string())?;
        SkeletonCatalog::load(self.worktree.join("skeletons"))
            .map_err(|errors| format!("the skeleton catalog is invalid: {}", issues_text(&errors)))
    }

    fn exists(&self, kind: RegistryKind, id: &str) -> bool {
        self.pin
            .current()
            .objects
            .iter()
            .any(|object| object.kind() == kind && object.id == id)
    }

    fn read_skeleton(&self, skeleton: &str) -> Result<serde_json::Value, String> {
        if skeleton == ENABLE_CAPABILITY {
            let off: Vec<serde_json::Value> = capabilities_off(&self.pin.current().objects)
                .into_iter()
                .map(
                    |(id, description)| serde_json::json!({ "id": id, "description": description }),
                )
                .collect();
            return Ok(serde_json::json!({
                "skeleton": skeleton,
                "destination": "an existing capability, plus the seat's slice and tool_refs",
                "variables": [{
                    "name": "seat",
                    "type": "id",
                    "required": true,
                    "meaning": "The seat that gets the capability as a tool (usually yourself).",
                }],
                "capabilitiesOff": off,
            }));
        }
        if skeleton == REMOVE_ENVIRONMENT {
            let declared: Vec<serde_json::Value> = self
                .pin
                .current()
                .objects
                .iter()
                .filter_map(|object| match &object.config {
                    ObjectConfig::Environment(environment) => Some(serde_json::json!({
                        "id": object.id,
                        "description": environment.description,
                        "enabled": environment.enabled,
                    })),
                    _ => None,
                })
                .collect();
            return Ok(serde_json::json!({
                "skeleton": skeleton,
                "destination": "a declared environment, removed by one validated commit",
                "variables": [],
                "environments": declared,
            }));
        }
        let kind = skeleton_kind(skeleton)?;
        let catalog = self.catalog()?;
        let contract = catalog
            .contract(kind)
            .ok_or_else(|| format!("{skeleton} has no contract"))?;
        let mut variables: Vec<serde_json::Value> = contract
            .variables()
            .map(|variable| {
                serde_json::json!({
                    "name": variable.name(),
                    "type": variable.variable_type(),
                    "required": variable.required,
                    "meaning": variable.meaning(),
                })
            })
            .collect();
        if kind == SkeletonKind::NewAlert {
            variables.push(serde_json::json!({
                "name": "workload",
                "type": "id",
                "required": false,
                "meaning": "A pod profile to watch instead of a container (then omit container); \
                            optional cadence_seconds for a profile without monitoring yet.",
            }));
        }
        Ok(serde_json::json!({
            "skeleton": skeleton,
            "destination": kind.destination(),
            "variables": variables,
        }))
    }

    fn author_blocking(
        &self,
        caller: &odin_domain::SeatId,
        request: &AuthorRequest,
    ) -> Result<AuthorChange, String> {
        if request.skeleton == ENABLE_CAPABILITY {
            return self.enable_capability(caller, request);
        }
        if request.skeleton == REMOVE_ENVIRONMENT {
            return self.remove_environment(caller, request);
        }
        let kind = skeleton_kind(&request.skeleton)?;
        let id = request.id.trim();
        let mut values: toml::Table = toml::from_str(&request.values)
            .map_err(|error| format!("values are not TOML lines: {error}"))?;
        let message = format!(
            "registry: {} '{id}' (runtime, by seat {caller})",
            request.skeleton
        );
        let (path, files, edits) =
            if kind == SkeletonKind::NewAlert && values.contains_key("workload") {
                self.pod_watchdog(id, &mut values)?
            } else {
                let compiled = self
                    .catalog()?
                    .compile_with_bindings(
                        FillRequest {
                            skeleton: kind,
                            destination_id: id.to_owned(),
                            values: values.into(),
                        },
                        &odin_cli::runtime_bindings::admitted_registry_bindings(),
                    )
                    .map_err(|errors| issues_text(&errors))?;
                let path = compiled
                    .destination
                    .relative_config()
                    .to_string_lossy()
                    .into_owned();
                match (compiled.destination, compiled.document) {
                    (
                        AuthoringDestination::RegistryObject { kind, id, .. },
                        CompiledDocument::Registry(_),
                    ) => {
                        if self.exists(kind, &id) {
                            return Err(format!("a {kind} named {id} already exists"));
                        }
                        let text = String::from_utf8(compiled.canonical_toml)
                            .map_err(|_| "the compiled declaration is not UTF-8".to_owned())?;
                        (path.clone(), vec![(path, text)], Vec::new())
                    }
                    (
                        AuthoringDestination::ContainerPatch {
                            container,
                            relative_config,
                        },
                        CompiledDocument::ContainerPatch(patch),
                    ) => {
                        let edit = Edit::new(path.clone(), path.clone(), move |text: &str| {
                            odin_registry::patch_container_source(
                                container.as_str(),
                                &relative_config,
                                text,
                                &patch,
                            )
                            .map_err(|errors| issues_text(&errors))
                        });
                        (path, Vec::new(), vec![edit])
                    }
                    _ => return Err("the compiled fill has no destination".to_owned()),
                }
            };
        let (published_revision, commit) = self.transact(&message, files, edits, &[])?;
        tracing::info!(
            "registry-author skeleton={} id={id} seat={caller} path={path} \
             revision={published_revision}",
            request.skeleton
        );
        Ok(AuthorChange {
            skeleton: request.skeleton.clone(),
            id: id.to_owned(),
            path,
            published_revision,
            commit,
        })
    }

    /// `enable-capability`: one commit turns the declared capability on (if
    /// it is off) and grants it to `seat` — its bound slice's capabilities
    /// and its own tool_refs. The shared transaction validates the whole
    /// candidate registry before anything publishes.
    fn enable_capability(
        &self,
        caller: &odin_domain::SeatId,
        request: &AuthorRequest,
    ) -> Result<AuthorChange, String> {
        let id = request.id.trim().to_owned();
        let mut values: toml::Table = toml::from_str(&request.values)
            .map_err(|error| format!("values are not TOML lines: {error}"))?;
        let seat = match values.remove("seat") {
            Some(toml::Value::String(seat)) => seat,
            _ => return Err("seat: name the seat that gets the capability".to_owned()),
        };
        if let Some(extra) = values.keys().next() {
            return Err(format!("{extra}: enable-capability takes only seat"));
        }
        let pinned = self.pin.current();
        let capability = pinned
            .objects
            .iter()
            .find_map(|object| match &object.config {
                ObjectConfig::Capability(capability) if object.id == id => Some(capability),
                _ => None,
            })
            .ok_or_else(|| format!("there is no capability {id}"))?;
        if !implemented(capability.implementation.as_deref()) {
            return Err(format!(
                "{id} is only a reserved contract with no implementation yet, so it cannot be turned on"
            ));
        }
        let declared_seat = pinned
            .objects
            .iter()
            .find_map(|object| match &object.config {
                ObjectConfig::Seat(declared) if object.id == seat => Some(declared),
                _ => None,
            });
        let declared_seat = declared_seat.ok_or_else(|| format!("there is no seat {seat}"))?;
        let slice = self
            .caller_slices
            .get(&seat)
            .ok_or_else(|| format!("seat {seat} is not bound to a slice on this host"))?
            .clone();
        if capability.enabled
            && declared_seat
                .tool_refs
                .iter()
                .any(|tool| tool.as_str() == id)
        {
            return Err(format!("{id} is already on for {seat}"));
        }
        let mut edits = Vec::new();
        let capability_path = format!("registry/capabilities/{id}/capability.toml");
        if !capability.enabled {
            edits.push(Edit::new(
                capability_path.clone(),
                capability_path.clone(),
                with_capability_enabled,
            ));
        }
        let slice_path = format!("registry/slices/{slice}/slice.toml");
        let granted = id.clone();
        edits.push(Edit::new(
            slice_path.clone(),
            slice_path,
            move |text: &str| with_item_in_array(text, None, "capabilities", &granted),
        ));
        let seat_path = format!("registry/seats/{seat}/seat.toml");
        let granted = id.clone();
        edits.push(Edit::new(
            seat_path.clone(),
            seat_path,
            move |text: &str| with_item_in_array(text, None, "tool_refs", &granted),
        ));
        let message = format!("registry: enable {id} for seat {seat} (runtime, by seat {caller})");
        let (published_revision, commit) = self.transact(&message, Vec::new(), edits, &[])?;
        tracing::info!(
            "registry-author enable-capability id={id} seat={seat} by={caller} \
             revision={published_revision}"
        );
        Ok(AuthorChange {
            skeleton: request.skeleton.clone(),
            id,
            path: capability_path,
            published_revision,
            commit,
        })
    }

    /// `new-alert` on a pod profile: the alert's fields are the skeleton's
    /// own (`alert_id` is the request id), parsed strictly.
    #[allow(clippy::type_complexity)]
    fn pod_watchdog(
        &self,
        id: &str,
        values: &mut toml::Table,
    ) -> Result<(String, Vec<(String, String)>, Vec<Edit>), String> {
        let workload = match values.remove("workload") {
            Some(toml::Value::String(workload)) => workload,
            _ => return Err("workload: must be a pod profile id".to_owned()),
        };
        if values.remove("container").is_some() {
            return Err("name either workload or container, not both".to_owned());
        }
        let cadence = match values.remove("cadence_seconds") {
            None => DEFAULT_CADENCE_SECONDS,
            Some(toml::Value::Integer(seconds)) if (5..=3600).contains(&seconds) => seconds,
            Some(_) => return Err("cadence_seconds: must be 5..=3600".to_owned()),
        };
        values.remove("alert_id");
        values.insert("id".to_owned(), toml::Value::String(id.to_owned()));
        let alert = ContainerAlertToml::deserialize(toml::Value::Table(values.clone()))
            .map_err(|error| format!("watchdog: {error}"))?;
        let declared = self.pin.current().objects.iter().any(|object| {
            object.id == workload && matches!(object.config, ObjectConfig::Workload(_))
        });
        if !declared {
            return Err(format!("there is no pod profile {workload}"));
        }
        let path = format!("registry/workloads/{workload}/profile.toml");
        let edit = Edit::new(path.clone(), path.clone(), move |text: &str| {
            append_pod_watchdog(text, &alert, cadence)
        });
        Ok((path, Vec::new(), vec![edit]))
    }
}

impl DaemonProjectRoute {
    /// `remove-environment`: one commit deletes the declared environment's
    /// directory; the shared transaction validates the whole candidate
    /// registry and the publication records the tombstone. A configured
    /// seat launch binding the environment refuses while it stands
    /// (composition refuses a launch naming a missing environment), as does
    /// any id that is not a declared environment.
    fn remove_environment(
        &self,
        caller: &odin_domain::SeatId,
        request: &AuthorRequest,
    ) -> Result<AuthorChange, String> {
        if !request.values.trim().is_empty() {
            return Err("remove-environment takes no values".to_owned());
        }
        let id = request.id.trim();
        let snapshot = self.pin.current();
        let declared = snapshot
            .objects
            .iter()
            .find(|object| object.id == id)
            .ok_or_else(|| format!("there is no environment {id}"))?;
        if declared.kind() != RegistryKind::Environment {
            return Err(format!(
                "{} is a {}, not an environment",
                id,
                declared.kind().as_str()
            ));
        }
        if let Some(seats) = self.harness_environments.get(id) {
            let seats: Vec<&str> = seats.iter().map(String::as_str).collect();
            return Err(format!(
                "environment {id} is bound by a configured seat launch ({}); rebind or remove \
                 that launch option first",
                seats.join(", ")
            ));
        }
        let directory = format!("registry/environments/{id}");
        let message = format!("registry: remove environment '{id}' (runtime, by seat {caller})");
        let (published_revision, commit) = self.transact(
            &message,
            Vec::new(),
            Vec::new(),
            std::slice::from_ref(&directory),
        )?;
        tracing::info!(
            "registry-author remove-environment id={id} seat={caller} \
             revision={published_revision}"
        );
        Ok(AuthorChange {
            skeleton: request.skeleton.clone(),
            id: id.to_owned(),
            path: format!("{directory}/environment.toml"),
            published_revision,
            commit,
        })
    }
}

impl RegistryAuthorRoute for DaemonProjectRoute {
    fn skeleton(&self, skeleton: &str) -> Result<serde_json::Value, String> {
        crate::project_authoring::blocking(|| self.read_skeleton(skeleton))
    }

    fn author(
        &self,
        caller: &odin_domain::SeatId,
        request: AuthorRequest,
    ) -> Result<AuthorChange, String> {
        let outcome = crate::project_authoring::blocking(|| self.author_blocking(caller, &request));
        if let Err(reason) = &outcome {
            // Log the refusal independently of the seat's turn response for diagnosis.
            tracing::error!(
                "registry-author refused skeleton={} id={} seat={caller} reason={reason}",
                request.skeleton,
                request.id
            );
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// web.search is on (SearXNG, Brave as the fallback),
    /// so enable-capability no longer offers it.
    #[test]
    fn web_search_is_on_and_no_longer_offered() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry");
        let objects = odin_registry::parse_objects(&odin_registry::walk(&root).objects).objects;
        assert!(capabilities_off(&objects)
            .iter()
            .all(|(id, _)| id != "web.search"));
    }

    #[test]
    fn enabling_flips_only_the_flag() {
        let text = "schema = \"odin.registry.v1\"\n# off until asked\nenabled = false\n\
                    description = \"enabled = false\"\n";
        let edited = with_capability_enabled(text).unwrap();
        assert_eq!(
            edited,
            "schema = \"odin.registry.v1\"\n# off until asked\nenabled = true\n\
             description = \"enabled = false\"\n"
        );
        assert_eq!(with_capability_enabled(&edited).unwrap(), edited);
        assert!(with_capability_enabled("schema = \"x\"\n").is_err());
    }

    const PROFILE: &str = r#"schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "Script pod emitting a residual."
harness = "script"
placement = ["scrape"]

[image]
reference = "docker.io/library/python:3.12-slim@sha256:eeb8088e67610b37583880c7627e3931f087cba55a35810819e34a398f624a47"

[script]
command = ["python3", "-c", "print(1)"]

[seat]
seat = "kubert"
project = "odin"

[network]
allow_hosts = []

[state]
path = "/state"
storage = "1Gi"

[export]
pod_path = "/export"
host_folder = "/srv/odin/export"

[brief]
text = "Prints residual lines."

[lifetime]
deadline_seconds = 900
"#;

    fn alert(id: &str) -> ContainerAlertToml {
        let table: toml::Table = toml::from_str(&format!(
            "id = \"{id}\"\ncondition = \"residual > 1e-3\"\nconsecutive_hits = 3\n\
             cooldown_seconds = 0\nseverity = \"warning\"\nslice = \"kubert-ops\"\n"
        ))
        .unwrap();
        ContainerAlertToml::deserialize(toml::Value::Table(table)).unwrap()
    }

    /// a watchdog lands on a pod profile from a DM — the
    /// profile's text is kept, monitoring opened when absent, and a second
    /// watchdog of the same id is refused.
    #[test]
    fn a_pod_watchdog_is_appended_to_the_profiles_monitoring() {
        let once = append_pod_watchdog(PROFILE, &alert("residual-high"), 30).unwrap();
        assert!(
            once.starts_with(PROFILE.trim_end()),
            "the declaration keeps its text"
        );
        let profile: WorkloadProfileToml = toml::from_str(&once).unwrap();
        let monitoring = profile.monitoring.expect("monitoring opened");
        assert_eq!(monitoring.cadence_seconds.get(), 30);
        assert_eq!(monitoring.watchdogs, vec![alert("residual-high")]);

        let twice = append_pod_watchdog(&once, &alert("residual-stuck"), 99).unwrap();
        let profile: WorkloadProfileToml = toml::from_str(&twice).unwrap();
        let monitoring = profile.monitoring.unwrap();
        assert_eq!(
            monitoring.cadence_seconds.get(),
            30,
            "an existing cadence stays"
        );
        assert_eq!(monitoring.watchdogs.len(), 2);

        let refused = append_pod_watchdog(&twice, &alert("residual-high"), 30).unwrap_err();
        assert!(refused.contains("already has a watchdog"), "{refused}");
    }
}
