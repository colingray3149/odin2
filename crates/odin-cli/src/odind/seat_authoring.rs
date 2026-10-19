//! Conversation seats create worker seat types under the same constraints as project creation.
//!
//! A created seat narrows an existing worker seat (its template). Its
//! actual runtime binding is projected through the daemon's canonical
//! adoption rules before deriving its authority. One commit declares
//! the seat, its `seat.ask.<seat>` delegation contract, a lane per project,
//! the container offer, and the coordinator's new grant to delegate to it.

use odin_hermes::runtime::projects::{
    SeatCreateRequest, SeatCreated, SeatProposeRequest, SeatProposed,
};
use odin_registry::{ObjectConfig, RegistryKind};

use super::{
    bindable_capabilities, with_item_in_array, without_item_in_array, DaemonProjectRoute, Edit,
    ACTIVATION,
};

/// A proposed (temporary) seat's narrowing: its tools and its expiry.
pub(super) struct Temporary {
    /// The template's tools it keeps; empty keeps them all.
    pub(super) tools: Vec<String>,
    /// UTC `YYYY-MM-DDTHH:MM:SSZ`.
    pub(super) expires_at: String,
    /// UTC `YYYY-MM-DDTHH:MM:SSZ` of the proposal.
    pub(super) proposed_at: String,
}

/// The validated plan of one seat creation, decided before any write.
pub(super) struct SeatPlan {
    seat: String,
    pub(super) files: Vec<(String, String)>,
    pub(super) edits: Vec<Edit>,
    lanes: Vec<String>,
    ask_tool: String,
    tools: Vec<String>,
    pub(super) slice: odin_domain::SliceId,
}

impl DaemonProjectRoute {
    pub(super) fn create_seat_blocking(
        &self,
        caller: &odin_domain::SeatId,
        request: &SeatCreateRequest,
    ) -> Result<SeatCreated, String> {
        let plan = self.seat_plan(caller, request, None)?;
        let message = format!("seat: create '{}' (runtime, by seat {caller})", plan.seat);
        let (published_revision, commit) =
            self.transact_with_admission(&message, plan.files, plan.edits, &[], |objects| {
                self.admit_planned_seat(objects, &plan.seat, &plan.slice)
            })?;
        Ok(SeatCreated {
            seat: plan.seat,
            lanes: plan.lanes,
            ask_tool: plan.ask_tool,
            published_revision,
            commit,
            activation: ACTIVATION.to_owned(),
        })
    }

    /// `seat.propose`: a seat creation narrowed to a
    /// subset of the template's tools, marked `[ephemeral]` with its expiry
    /// and proposer, retired again by the daemon's retire pass.
    pub(super) fn propose_seat_blocking(
        &self,
        caller: &odin_domain::SeatId,
        request: &SeatProposeRequest,
    ) -> Result<SeatProposed, String> {
        if !(1..=24).contains(&request.ttl_hours) {
            return Err("a temporary seat lives 1 to 24 hours".to_owned());
        }
        let now = time::OffsetDateTime::now_utc();
        let expires = now + time::Duration::hours(i64::from(request.ttl_hours));
        let temporary = Temporary {
            tools: request.tools.clone(),
            expires_at: utc_stamp(expires),
            proposed_at: utc_stamp(now),
        };
        let plan = self.seat_plan(caller, &request.seat, Some(&temporary))?;
        let message = format!(
            "seat: propose '{}' (temporary until {}, by seat {caller})",
            plan.seat, temporary.expires_at
        );
        let tools = plan.tools.clone();
        let (published_revision, commit) =
            self.transact_with_admission(&message, plan.files, plan.edits, &[], |objects| {
                self.admit_planned_seat(objects, &plan.seat, &plan.slice)
            })?;
        Ok(SeatProposed {
            created: SeatCreated {
                seat: plan.seat,
                lanes: plan.lanes,
                ask_tool: plan.ask_tool,
                published_revision,
                commit,
                activation: ACTIVATION.to_owned(),
            },
            tools,
            expires_at: temporary.expires_at,
        })
    }

    pub(super) fn admit_planned_seat(
        &self,
        objects: &[odin_registry::RegistryObject],
        seat: &str,
        slice: &odin_domain::SliceId,
    ) -> Result<(), String> {
        let future = crate::projection::future_brain_config(&self.admission_config, objects);
        if !future
            .seats
            .iter()
            .any(|binding| binding.seat.as_str() == seat && &binding.slice == slice)
        {
            return Err(format!(
                "{seat} future binding changed after helper authority was planned"
            ));
        }
        Ok(())
    }

    /// Every enabled `[ephemeral]` seat with its expiry and, when declared,
    /// its proposal time.
    pub(crate) fn declared_ephemeral_proposals(&self) -> Vec<(String, i64, Option<i64>)> {
        let snapshot = self.pin.current();
        snapshot
            .objects
            .iter()
            .filter_map(|object| match &object.config {
                ObjectConfig::Seat(seat) if seat.enabled => {
                    let ephemeral = seat.ephemeral.as_ref()?;
                    let expires = ephemeral.expires_at_unix()?;
                    Some((object.id.clone(), expires, ephemeral.proposed_at_unix()))
                }
                _ => None,
            })
            .collect()
    }

    /// Every enabled `[ephemeral]` seat and its expiry.
    pub(super) fn declared_ephemeral_seats(&self) -> Vec<(String, i64)> {
        let snapshot = self.pin.current();
        snapshot
            .objects
            .iter()
            .filter_map(|object| match &object.config {
                ObjectConfig::Seat(seat) if seat.enabled => seat
                    .ephemeral
                    .as_ref()
                    .and_then(|ephemeral| ephemeral.expires_at_unix())
                    .map(|expires| (object.id.clone(), expires)),
                _ => None,
            })
            .collect()
    }

    /// Retires one `[ephemeral]` seat with the exact inverse of its
    /// proposal: its seat, delegation contract and lanes are removed; the
    /// container offer and the proposer's grant lose it.
    pub(super) fn retire_seat_blocking(
        &self,
        seat: &str,
        reason: &str,
    ) -> Result<(u64, String), String> {
        let (removals, edits) = self.retire_plan(seat)?;
        let message = format!("seat: retire '{seat}' (temporary, {reason})");
        self.transact(&message, Vec::new(), edits, &removals)
    }

    /// The inverse plan of a proposal, decided read-only.
    pub(super) fn retire_plan(&self, seat: &str) -> Result<(Vec<String>, Vec<Edit>), String> {
        let snapshot = self.pin.current();
        let declared = snapshot
            .objects
            .iter()
            .find(|object| object.kind() == RegistryKind::Seat && object.id == seat)
            .ok_or_else(|| format!("there is no seat {seat}"))?;
        let ObjectConfig::Seat(declaration) = &declared.config else {
            return Err(format!("{seat} is not a seat"));
        };
        let ephemeral = declaration
            .ephemeral
            .as_ref()
            .ok_or_else(|| format!("{seat} is not a temporary seat"))?;
        let proposer = ephemeral.proposed_by.as_str();
        let caller_slice = self
            .caller_slices
            .get(proposer)
            .ok_or_else(|| format!("{proposer} has no configured slice"))?;
        let ask = format!("seat.ask.{seat}");
        let ask_tool = ask.replace('.', "_");
        let mut removals = vec![
            format!("registry/seats/{seat}"),
            format!("registry/capabilities/{ask}"),
        ];
        for object in &snapshot.objects {
            if let ObjectConfig::Lane(lane) = &object.config {
                if lane.default_seat.as_str() == seat {
                    removals.push(format!("registry/lanes/{}", object.id));
                }
            }
        }
        let item =
            |path: String, table: Option<&'static str>, key: &'static str, value: String| Edit {
                source: path.clone(),
                path,
                apply: Box::new(move |text: &str| without_item_in_array(text, table, key, &value)),
            };
        let mut edits = Vec::new();
        for object in &snapshot.objects {
            if let ObjectConfig::Container(container) = &object.config {
                if container.seats_offered.iter().any(|id| id.as_str() == seat) {
                    edits.push(item(
                        format!("registry/containers/{}/container.toml", object.id),
                        None,
                        "seats_offered",
                        seat.to_owned(),
                    ));
                }
            }
        }
        edits.push(item(
            format!("registry/seats/{proposer}/seat.toml"),
            None,
            "tool_refs",
            ask.clone(),
        ));
        edits.push(item(
            format!("registry/slices/{caller_slice}/slice.toml"),
            None,
            "capabilities",
            ask,
        ));
        edits.push(item(
            format!("registry/slices/{caller_slice}/slice.toml"),
            Some("tools"),
            "allow",
            ask_tool,
        ));
        Ok((removals, edits))
    }

    /// Validate before writing any files.
    pub(super) fn seat_plan(
        &self,
        caller: &odin_domain::SeatId,
        request: &SeatCreateRequest,
        temporary: Option<&Temporary>,
    ) -> Result<SeatPlan, String> {
        let snapshot = self.pin.current();
        let object = |kind: RegistryKind, id: &str| {
            snapshot
                .objects
                .iter()
                .find(|object| object.kind() == kind && object.id == id)
        };
        let seat_of = |id: &str| match object(RegistryKind::Seat, id).map(|object| &object.config) {
            Some(ObjectConfig::Seat(seat)) => Some(seat.as_ref()),
            _ => None,
        };
        match seat_of(caller.as_str()) {
            Some(seat) if seat.conversation.is_some() => {}
            _ => return Err("only the owner-facing conversation seat creates seats".to_owned()),
        }
        let caller_slice = self
            .caller_slices
            .get(caller.as_str())
            .ok_or("the conversation seat has no configured slice")?;
        let seat = request.seat.as_str();
        let valid_id = (2..=31).contains(&seat.len())
            && seat.starts_with(|c: char| c.is_ascii_lowercase())
            && seat
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_id || seat.parse::<odin_domain::SeatId>().is_err() {
            return Err(format!("{seat:?} is not a valid seat id"));
        }
        let ask = format!("seat.ask.{seat}");
        if seat_of(seat).is_some() || object(RegistryKind::Capability, &ask).is_some() {
            return Err(format!("a seat named {seat} already exists"));
        }
        let template_id = request.template.as_str();
        let template =
            seat_of(template_id).ok_or_else(|| format!("there is no seat {template_id}"))?;
        if !template.enabled || template.conversation.is_some() {
            return Err(format!("{template_id} cannot be copied into a new seat"));
        }
        let allowed = bindable_capabilities(&self.worktree, &self.sync)?;
        if let Some(capability) = template
            .tool_refs
            .iter()
            .find(|capability| !allowed.iter().any(|held| held == capability.as_str()))
        {
            return Err(format!(
                "{template_id} holds {capability}, beyond what a created seat may hold"
            ));
        }
        // A temporary seat keeps only the template tools it names: a
        // subset, never a widening.
        let tools: Vec<String> = match temporary {
            Some(temporary) if !temporary.tools.is_empty() => {
                if let Some(extra) = temporary.tools.iter().find(|tool| {
                    !template
                        .tool_refs
                        .iter()
                        .any(|held| held.as_str() == tool.as_str())
                }) {
                    return Err(format!(
                        "{extra} is not one of {template_id}'s tools; a temporary seat may only \
                         keep a subset of its template's"
                    ));
                }
                let mut tools = temporary.tools.clone();
                tools.sort();
                tools.dedup();
                tools
            }
            _ => template
                .tool_refs
                .iter()
                .map(|tool| tool.as_str().to_owned())
                .collect(),
        };
        let container = snapshot
            .objects
            .iter()
            .find(|object| match &object.config {
                ObjectConfig::Container(container) => container
                    .seats_offered
                    .iter()
                    .any(|offered| offered.as_str() == template_id),
                _ => false,
            })
            .ok_or_else(|| format!("{template_id} runs in no declared container"))?
            .id
            .clone();
        let mut projects: Vec<&str> = Vec::new();
        let mut lanes = Vec::new();
        let mut files = Vec::new();
        for project in &request.projects {
            if projects.contains(&project.as_str()) {
                continue;
            }
            match object(RegistryKind::Project, project).map(|object| &object.config) {
                Some(ObjectConfig::Project(declared)) if declared.enabled => {}
                _ => return Err(format!("there is no project {project}")),
            }
            if !template
                .project_scope
                .iter()
                .any(|held| held.as_str() == project)
            {
                return Err(format!(
                    "{project} is outside {template_id}'s project scope"
                ));
            }
            let lane = format!("{seat}-{project}");
            if lane.parse::<odin_domain::LaneId>().is_err()
                || object(RegistryKind::Lane, &lane).is_some()
            {
                return Err(format!("the lane {lane} cannot be declared"));
            }
            files.push((
                format!("registry/lanes/{lane}/lane.toml"),
                format!(
                    "schema = \"odin.registry.v1\"\nkind = \"lane\"\nenabled = true\n\
                     description = {}\nproject = \"{project}\"\nfamily = \"engine\"\n\
                     default_seat = \"{seat}\"\nqueue = \"interactive\"\n\
                     requires_independent_review = false\n",
                    quoted(&format!("{seat} work on {project}")),
                ),
            ));
            lanes.push(lane);
            projects.push(project);
        }
        if projects.is_empty() {
            return Err("a seat needs at least one project".to_owned());
        }
        let purpose = request.purpose.trim();
        files.push((
            format!("registry/capabilities/{ask}/capability.toml"),
            format!(
                "schema = \"odin.registry.v1\"\nkind = \"capability\"\nenabled = true\n\
                 implementation = \"builtin\"\nversion = 1\ndescription = {}\n\
                 handler = {{ id = \"seat_ask\" }}\ndelegate_to = \"{seat}\"\n\
                 input_schema = \"schemas/capability/seat.ask.input.json\"\n\
                 output_schema = \"schemas/capability/seat.ask.output.json\"\n\
                 effect_class = \"R3\"\nseat_tags = [\"coordinator\"]\ntimeout_seconds = 30\n\
                 idempotency = \"required\"\nretry = {{ max_attempts = 0 }}\n\
                 approval_policy = \"operator\"\napproval_decider = \"declaration\"\n\
                 evidence_extractor = {{ id = \"odin_hermes_seat_ask_evidence\" }}\n",
                quoted(&format!(
                    "Ask {seat}: {purpose} Work stays within the selected project's declared \
                     permissions and appears in its own terminal tab; a retry continues the \
                     same task rather than starting another."
                )),
            ),
        ));
        let ask_tool = ask.replace('.', "_");
        let mut candidate = snapshot.objects.clone();
        let mut helper = object(RegistryKind::Seat, template_id)
            .ok_or_else(|| format!("there is no seat {template_id}"))?
            .clone();
        helper.id = seat.to_owned();
        candidate.push(helper);
        for object in &mut candidate {
            if object.id == container {
                if let ObjectConfig::Container(declared) = &mut object.config {
                    declared.seats_offered.insert(
                        seat.parse()
                            .map_err(|error| format!("helper seat: {error}"))?,
                    );
                }
            }
        }
        let future = crate::projection::future_brain_config(&self.admission_config, &candidate);
        let future_binding = future
            .seats
            .iter()
            .find(|binding| binding.seat.as_str() == seat)
            .ok_or_else(|| format!("{seat} has no future runtime binding"))?;
        let template_binding = self
            .admission_config
            .seats
            .iter()
            .find(|binding| binding.seat.as_str() == template_id)
            .ok_or_else(|| format!("{template_id} has no runtime binding"))?;
        let slice_of = |id: &str| match object(RegistryKind::Slice, id).map(|o| &o.config) {
            Some(ObjectConfig::Slice(slice)) => Ok(slice.as_ref()),
            _ => Err(format!("there is no slice {id}")),
        };
        let template_slice = slice_of(template_binding.slice.as_str())?;
        let future_slice = slice_of(future_binding.slice.as_str())?;
        compatible_slices(template_slice, future_slice)?;
        let mut policies = crate::projection::bound_brain_policies(
            &self.admission_config,
            snapshot.revision,
            &snapshot.objects,
            [(&template_binding.seat, &template_binding.slice)],
        )?;
        let knowledge = match policies.remove(&template_binding.seat) {
            Some(policy) => match policy.knowledge {
                Some(knowledge) => {
                    let ceiling = future_slice
                        .knowledge
                        .as_ref()
                        .ok_or("future slice has no knowledge authority")?;
                    let mut allowed = policy.seat_global_sources;
                    for project in &projects {
                        if let Some(ObjectConfig::Project(declared)) =
                            object(RegistryKind::Project, project).map(|o| &o.config)
                        {
                            allowed.extend(declared.memory_namespaces.iter().cloned());
                        }
                    }
                    let atlas_sources = knowledge
                        .atlas_sources
                        .into_iter()
                        .filter(|source| {
                            ceiling.atlas_sources.contains(source) && allowed.contains(source)
                        })
                        .collect::<std::collections::BTreeSet<_>>();
                    if (knowledge.required || ceiling.required) && atlas_sources.is_empty() {
                        return Err("helper narrowing leaves required knowledge empty".to_owned());
                    }
                    Some(odin_registry::schema::SeatKnowledgeToml {
                        atlas_sources,
                        required_tags: knowledge.required_tags,
                        denied_tags: knowledge.denied_tags,
                        top_k: knowledge.top_k.min(ceiling.top_k),
                    })
                }
                None => None,
            },
            None if template_slice.knowledge.is_none()
                && template.knowledge.is_none()
                && template.brain_scope.is_empty() =>
            {
                None
            }
            None => {
                return Err(
                    "template knowledge requires a configured canonical brain policy".to_owned(),
                )
            }
        };
        let new_seat = {
            let expected_template = template.clone();
            let (seat, purpose) = (seat.to_owned(), purpose.to_owned());
            let projects: Vec<String> = projects.iter().map(|p| (*p).to_owned()).collect();
            let narrowing = temporary.map(|temporary| Narrowing {
                tools: tools.clone(),
                expires_at: temporary.expires_at.clone(),
                proposed_by: caller.to_string(),
                proposed_at: temporary.proposed_at.clone(),
            });
            Edit {
                source: format!("registry/seats/{template_id}/seat.toml"),
                path: format!("registry/seats/{seat}/seat.toml"),
                apply: Box::new(move |template: &str| {
                    let current: odin_registry::schema::SeatToml = toml::from_str(template)
                        .map_err(|error| format!("template seat: {error}"))?;
                    if current != expected_template {
                        return Err(
                            "template changed while planning helper authority; retry the request"
                                .to_owned(),
                        );
                    }
                    derived_seat(
                        template,
                        &purpose,
                        &projects,
                        knowledge.as_ref(),
                        narrowing.as_ref(),
                    )
                }),
            }
        };
        let item =
            |path: String, table: Option<&'static str>, key: &'static str, value: String| Edit {
                source: path.clone(),
                path,
                apply: Box::new(move |text: &str| with_item_in_array(text, table, key, &value)),
            };
        let mut edits = Vec::new();
        let mut guarded_slices = std::collections::BTreeSet::new();
        for (slice_id, expected) in [
            (&template_binding.slice, template_slice),
            (&future_binding.slice, future_slice),
        ] {
            if !guarded_slices.insert(slice_id) {
                continue;
            }
            let path = format!("registry/slices/{slice_id}/slice.toml");
            let expected = expected.clone();
            edits.push(Edit {
                source: path.clone(),
                path,
                apply: Box::new(move |text: &str| {
                    let current: odin_registry::schema::SliceToml =
                        toml::from_str(text).map_err(|error| format!("helper slice: {error}"))?;
                    if current != expected {
                        return Err(
                            "slice changed while planning helper authority; retry the request"
                                .to_owned(),
                        );
                    }
                    Ok(text.to_owned())
                }),
            });
        }
        let expected_container =
            match object(RegistryKind::Container, &container).map(|object| &object.config) {
                Some(ObjectConfig::Container(declared)) => declared.clone(),
                _ => return Err(format!("there is no container {container}")),
            };
        let container_path = format!("registry/containers/{container}/container.toml");
        edits.push(Edit {
            source: container_path.clone(),
            path: container_path,
            apply: Box::new(move |text: &str| {
                let current: odin_registry::schema::ContainerToml =
                    toml::from_str(text).map_err(|error| format!("helper container: {error}"))?;
                if current != *expected_container {
                    return Err(
                        "container changed while planning helper binding; retry the request"
                            .to_owned(),
                    );
                }
                Ok(text.to_owned())
            }),
        });
        for project in &projects {
            let expected_project = match object(RegistryKind::Project, project).map(|o| &o.config) {
                Some(ObjectConfig::Project(declared)) => declared.clone(),
                _ => return Err(format!("there is no project {project}")),
            };
            let path = format!("registry/projects/{project}/project.toml");
            edits.push(Edit {
                source: path.clone(),
                path,
                apply: Box::new(move |text: &str| {
                    let current: odin_registry::schema::ProjectToml =
                        toml::from_str(text).map_err(|error| format!("helper project: {error}"))?;
                    if current != *expected_project {
                        return Err(
                            "project changed while planning helper authority; retry the request"
                                .to_owned(),
                        );
                    }
                    Ok(text.to_owned())
                }),
            });
        }
        edits.extend([
            new_seat,
            item(
                format!("registry/containers/{container}/container.toml"),
                None,
                "seats_offered",
                seat.to_owned(),
            ),
            item(
                format!("registry/seats/{caller}/seat.toml"),
                None,
                "tool_refs",
                ask.clone(),
            ),
            item(
                format!("registry/slices/{caller_slice}/slice.toml"),
                None,
                "capabilities",
                ask.clone(),
            ),
            item(
                format!("registry/slices/{caller_slice}/slice.toml"),
                Some("tools"),
                "allow",
                ask_tool.clone(),
            ),
        ]);
        Ok(SeatPlan {
            seat: seat.to_owned(),
            files,
            edits,
            lanes,
            ask_tool,
            tools,
            slice: future_binding.slice.clone(),
        })
    }
}

fn quoted(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

/// A temporary seat's tools, expiry and proposer, written into its
/// declaration.
struct Narrowing {
    tools: Vec<String>,
    expires_at: String,
    proposed_by: String,
    proposed_at: String,
}

/// Keeps template restrictions while materializing its narrowed canonical knowledge.
fn derived_seat(
    template: &str,
    purpose: &str,
    projects: &[String],
    knowledge: Option<&odin_registry::schema::SeatKnowledgeToml>,
    narrowing: Option<&Narrowing>,
) -> Result<String, String> {
    let mut seat: toml::Table =
        toml::from_str(template).map_err(|error| format!("template seat: {error}"))?;
    seat.insert("description".into(), purpose.into());
    seat.insert(
        "project_scope".into(),
        toml::Value::Array(projects.iter().map(|p| p.as_str().into()).collect()),
    );
    seat.insert(
        "brain_scope".into(),
        toml::Value::Array(
            knowledge
                .into_iter()
                .flat_map(|policy| &policy.atlas_sources)
                .map(|source| source.as_str().into())
                .collect(),
        ),
    );
    if seat
        .get("profile_namespace")
        .and_then(toml::Value::as_str)
        .is_some_and(|profile| {
            !knowledge.is_some_and(|policy| {
                policy
                    .atlas_sources
                    .iter()
                    .any(|source| source.as_str() == profile)
            })
        })
    {
        seat.remove("profile_namespace");
    }
    if let Some(knowledge) = knowledge {
        seat.insert(
            "knowledge".into(),
            toml::Value::try_from(knowledge)
                .map_err(|error| format!("helper knowledge: {error}"))?,
        );
    }
    if let Some(narrowing) = narrowing {
        seat.insert(
            "tool_refs".into(),
            toml::Value::Array(narrowing.tools.iter().map(|t| t.as_str().into()).collect()),
        );
        if let Some(always) = seat
            .get_mut("tools")
            .and_then(toml::Value::as_table_mut)
            .and_then(|tools| tools.get_mut("always"))
            .and_then(toml::Value::as_array_mut)
        {
            always.retain(|entry| {
                entry.as_str().is_some_and(|entry| {
                    narrowing
                        .tools
                        .iter()
                        .any(|tool| odin_registry::schema::always_covers(entry, tool))
                })
            });
        }
        let mut ephemeral = toml::Table::new();
        ephemeral.insert("expires_at".into(), narrowing.expires_at.as_str().into());
        ephemeral.insert("proposed_by".into(), narrowing.proposed_by.as_str().into());
        ephemeral.insert("proposed_at".into(), narrowing.proposed_at.as_str().into());
        seat.insert("ephemeral".into(), toml::Value::Table(ephemeral));
    }
    toml::to_string(&seat).map_err(|error| format!("derived seat: {error}"))
}

fn compatible_slices(
    template: &odin_registry::schema::SliceToml,
    future: &odin_registry::schema::SliceToml,
) -> Result<(), String> {
    let knowledge_matches = match (&template.knowledge, &future.knowledge) {
        (Some(template), Some(future)) => {
            let mut bounded = future.clone();
            bounded.atlas_sources = template.atlas_sources.clone();
            bounded.top_k = template.top_k;
            &bounded == template
        }
        (None, None) => true,
        _ => false,
    };
    if !knowledge_matches
        || template.context != future.context
        || template.tools != future.tools
        || template.live != future.live
        || template.budget != future.budget
    {
        return Err("future binding has incompatible slice-only template authority".to_owned());
    }
    Ok(())
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ`.
pub(super) fn utc_stamp(at: time::OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}
